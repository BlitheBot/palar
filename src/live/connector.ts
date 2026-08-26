/**
 * Live connector: actually spawns (stdio) or connects to (SSE) a discovered
 * MCP server and speaks the real protocol to it, using
 * @modelcontextprotocol/sdk's Client. This is the piece that did not exist
 * before this module — previously palar only read the JSON files that
 * describe a server, never ran one.
 *
 * stdio targets run inside a Docker container (sandbox.ts), not directly
 * on this host — Docker is mandatory here, with no unsandboxed fallback.
 * What that does and doesn't cover is documented in sandbox.ts and
 * README.md's "Live scanning" section. SSE targets have no local process to
 * sandbox; whether they are PROBED at all is a separate decision made on
 * loopback-vs-remote grounds in eligibility.ts, not here.
 *
 * Two callers, deliberately sharing one connect path:
 *   - liveScan.ts (`palar live`) connects and then *probes* — it calls
 *     tools with crafted input and waits for an oracle callback.
 *   - enumerate.ts (`palar scan --from-command` / `--from-url`) connects,
 *     calls listTools(), and disconnects. It never calls a tool.
 * Everything about establishing the connection is identical between them,
 * so it lives here once; what differs is entirely what the caller does
 * with the Client afterwards, plus whether the sandbox's firewall opens a
 * port for a callback at all (see TargetSandbox.installFirewall).
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { MCPServerConfig } from "../core/types.js";
import { VERSION } from "../core/version.js";
import type { TargetSandbox } from "./sandbox.js";

export interface LiveConnection {
  client: Client;
  /** Child process pid for stdio targets; null for SSE (no local process). */
  pid: number | null;
  transportKind: "stdio" | "sse";
  /**
   * How long palar's own container took to reach a running state, stdio
   * only (0 for SSE). Reported separately from the handshake so a slow
   * Docker daemon is never read as a slow target.
   */
  containerStartMs: number;
  /** Graceful close, then an unconditional kill-by-pid backstop for stdio. */
  close(): Promise<void>;
}

export interface ConnectOptions {
  /**
   * Milliseconds to wait for the target to answer the MCP handshake.
   *
   * For a stdio target the clock starts when the CONTAINER IS RUNNING, not
   * when `docker run` was invoked — see TargetSandbox.waitForContainerRunning().
   * palar's own container-start latency has its own budget below, because
   * charging it here meant a cold Docker daemon reported as a target that
   * never answered.
   */
  connectTimeoutMs?: number;
  /**
   * Milliseconds to wait for palar's own sandbox container to reach a
   * running state, stdio only. Separate from connectTimeoutMs on purpose:
   * this one measures this machine, that one measures the target.
   */
  containerStartTimeoutMs?: number;
  /** Required for stdio targets: the sandbox the target's container runs in. */
  sandbox?: TargetSandbox;
  /** Required for stdio targets: read-only mount root for the container (the target's own directory). */
  targetDir?: string;
}

export class ConnectorError extends Error {}

async function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new ConnectorError(`${label} timed out after ${ms}ms`)), ms);
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    clearTimeout(timer!);
  }
}

/**
 * `client.connect()`, with the SDK's own request timeout raised to match
 * palar's.
 *
 * `connect()` sends an `initialize` request, and the SDK bounds that with
 * its own DEFAULT_REQUEST_TIMEOUT_MSEC of 60s unless told otherwise. So
 * `--connect-timeout-ms 90000` did not mean 90 seconds: at 60s the SDK
 * aborted with `MCP error -32001: Request timed out`, and palar's own
 * ceiling never got to apply. A flag that silently cannot exceed a limit it
 * does not mention is worse than no flag — measured against
 * desktop-commander, which loads remote feature flags before answering
 * `initialize` and so takes longer than 60s to hand back a tool list when
 * the sandbox denies it that network.
 */
function connectWithTimeout(
  client: Client,
  transport: Transport,
  connectTimeoutMs: number
): Promise<void> {
  return client.connect(transport, { timeout: connectTimeoutMs });
}

/**
 * Connects, and on failure closes the transport before rethrowing.
 *
 * Without this, a target that cannot be reached leaves the process hanging
 * forever instead of reporting the failure and exiting: `client.connect()`
 * rejects, the transport it was handed is unreachable from the caller (it
 * was created in here), and its open socket or timer keeps Node's event
 * loop alive. The failure is printed correctly and then nothing happens —
 * which in CI is indistinguishable from a scan that is still working, and
 * is the worst of both outcomes. `close()` is best-effort: whatever went
 * wrong with the connect is the error worth reporting, not a secondary
 * failure while tidying up after it.
 */
async function connectOrClose(
  client: Client,
  transport: Transport,
  connectTimeoutMs: number,
  label: string
): Promise<void> {
  try {
    await withTimeout(connectWithTimeout(client, transport, connectTimeoutMs), connectTimeoutMs, label);
  } catch (err) {
    try {
      await transport.close();
    } catch {
      // Already dead, or never opened.
    }
    throw err;
  }
}

/**
 * Collects a bounded tail of a stdio target's own stderr, so a failure to
 * connect can say *why*.
 *
 * Without this, every way a containerized target can die before answering
 * the handshake — a missing dependency, a bad argument, a runtime the image
 * doesn't have — surfaces identically as `MCP error -32000: Connection
 * closed`, and the target has already printed the actual reason to a pipe
 * nobody read. "Never reached" is only a useful verdict if it comes with
 * the evidence; without it the user cannot tell an unsupported invocation
 * from a broken server from a palar bug.
 *
 * Bounded because the target chooses how much it writes: a chatty or
 * hostile server must not be able to grow this process's memory through a
 * pipe palar opened. The tail is kept rather than the head — the reason a
 * process died is at the end of its output.
 */
class StderrCapture {
  private static readonly LIMIT = 4_000;
  private static readonly ATTACH_RETRIES = 10;
  private text = "";

  /**
   * StdioClientTransport only exposes `.stderr` once it has spawned, which
   * happens inside client.connect(). Attaching is therefore attempted
   * immediately (start() runs synchronously at the top of connect()) and
   * retried briefly if the stream isn't there yet. Data written before the
   * listener attaches is not lost: a paused stream buffers it.
   */
  attach(transport: StdioClientTransport, attempt = 0): void {
    const stream = transport.stderr;
    if (!stream) {
      if (attempt >= StderrCapture.ATTACH_RETRIES) return;
      // unref'd so a target that never spawns cannot hold the event loop
      // open and turn a clean failure into a hang.
      setTimeout(() => this.attach(transport, attempt + 1), 50).unref();
      return;
    }
    stream.on("data", (chunk: Buffer | string) => {
      this.text = (this.text + chunk.toString()).slice(-StderrCapture.LIMIT);
    });
  }

  /** Appended to a connect error, or empty when the target said nothing. */
  suffix(): string {
    const trimmed = this.text.trim();
    return trimmed.length === 0
      ? ""
      : `\n--- target stderr (last ${trimmed.length} chars) ---\n${trimmed}`;
  }
}

/** Force-kill a pid, ignoring "already dead" errors. Windows has no real signals; Node maps this to termination either way. */
function forceKill(pid: number): void {
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Already exited, or never started — nothing to clean up.
  }
}

export async function connectLive(
  server: MCPServerConfig,
  opts: ConnectOptions = {}
): Promise<LiveConnection> {
  // 90s. A stdio target's connect covers container start plus whatever the
  // target chooses to do before it answers the MCP handshake, and the
  // second term is the one that decides this number — it is the target's
  // behaviour, not palar's, and it varies by an order of magnitude across
  // real servers. Measured on Docker Desktop, connect-to-tool-list:
  //
  //   playwright-mcp        1.9-3.2s
  //   server-memory         5.4-7.0s
  //   server-everything     5.9-8.0s
  //   server-filesystem     5.4-10.1s
  //   vuln-server fixture   7.8-11.2s   (plain JS, no build step)
  //   desktop-commander     46.0s
  //
  // desktop-commander is the case that forced this. It fetches remote
  // feature flags before answering `initialize`, and the sandbox denies it
  // that network — so it waits out its own HTTP timeout and only then
  // replies. At the previous 30s default it never replied in time: the most
  // dangerous server in the sample reported as a connect failure and
  // produced nothing, every run. 90s is ~2x the worst legitimate case
  // observed, which is the right shape for a backstop against a target that
  // will never answer — it must sit well clear of slow starts rather than
  // tightly bound them, because the cost of being too tight is a silent
  // non-result and the cost of being too loose is waiting.
  //
  // Note this is above the SDK's own 60s DEFAULT_REQUEST_TIMEOUT_MSEC,
  // which is why connectWithTimeout() exists — without it a 90s ceiling
  // would be a lie that aborted at 60s. Callers who need a tighter bound
  // pass connectTimeoutMs (`--connect-timeout-ms`); note liveScan.ts's
  // overall ceiling preempts this one if it is the smaller of the two.
  const connectTimeoutMs = opts.connectTimeoutMs ?? 90_000;
  // palar's own container start, kept out of the number above. Generous
  // because it is bounded by this machine's Docker daemon rather than by
  // anything palar or the target controls: a warm daemon does this in under
  // two seconds (every target in the sample), and a cold Docker Desktop /
  // WSL2 has been measured taking tens of seconds. It only has to be large
  // enough that "the daemon was slow" never gets reported as "the target
  // never answered".
  const containerStartTimeoutMs = opts.containerStartTimeoutMs ?? 120_000;
  // The identity the target sees in the MCP handshake, and often the only
  // thing it records about who connected. Two properties matter:
  //
  //  - The version is read from package.json (core/version.ts) rather than
  //    written here. The literal "0.1.0" that used to sit in this line was
  //    still being sent by palar 0.2.0 — the same drift that made the CLI
  //    misreport its own --version, reproduced in the one place a *target*
  //    can see it. A hardcoded version string does not stay true.
  //  - The name is "palar", not "palar-live-scanner", because this
  //    connector now serves two callers with genuinely different
  //    behavior: `palar live`, which probes, and `scan --from-command` /
  //    `scan --from-url`, which only enumerate and never call a tool.
  //    Announcing "live-scanner" to a server that is about to be read and
  //    nothing more overstates what is happening, and the product name is
  //    accurate for both.
  const client = new Client({ name: "palar", version: VERSION });

  if (server.transport === "sse") {
    if (!server.url) {
      throw new ConnectorError(
        `server "${server.name}" declares transport "sse" but no "url" — cannot connect`
      );
    }
    const transport: Transport = new SSEClientTransport(new URL(server.url));
    await connectOrClose(client, transport, connectTimeoutMs, `connect to "${server.name}" (SSE)`);
    return {
      client,
      pid: null,
      transportKind: "sse",
      // Nothing local is started for SSE, so there is no container to wait
      // for and nothing of palar's own to subtract.
      containerStartMs: 0,
      async close() {
        await transport.close();
      },
    };
  }

  // Default to stdio — the only transport the vuln-server fixture and most
  // local MCP servers use today.
  if (!server.command) {
    throw new ConnectorError(
      `server "${server.name}" declares no "command" — nothing to spawn over stdio`
    );
  }
  if (!opts.sandbox || !opts.targetDir) {
    // Should be unreachable: liveScan.ts always builds a sandbox before
    // calling connectLive() for a stdio target. Guarded explicitly rather
    // than spawning server.command directly, since that fallback is
    // exactly the unsandboxed path this module no longer has.
    throw new ConnectorError(
      `server "${server.name}" is a stdio target but no sandbox was provided — refusing to run it unsandboxed`
    );
  }

  const dockerArgs = opts.sandbox.dockerRunArgs(server, opts.targetDir);
  const transport = new StdioClientTransport({
    command: "docker",
    args: dockerArgs,
    // No `env` override here: this spawns the `docker` CLI client on the
    // host, not the target itself. The target's declared env (server.env)
    // is delivered into the container via `-e` flags baked into
    // dockerArgs (see sandbox.ts, which reuses buildCleanEnv for that) —
    // passing it to the docker CLI's own process environment would do
    // nothing useful and risks colliding with vars the CLI itself reads
    // (DOCKER_HOST, HOME). The SDK's own default allowlist environment
    // (see env.ts's docstring) is enough for the CLI to run.
    stderr: "pipe",
  });

  // The connect is kicked off first and awaited below, so that the stderr
  // listener attaches while the target is starting rather than after it has
  // already failed. See StderrCapture for why that ordering is safe.
  //
  // The SDK's own request timeout has to cover BOTH phases, since its clock
  // starts here: if it were given only connectTimeoutMs it would abort
  // mid-handshake for any target whose container was slow to start, which
  // is precisely the confusion the two-phase split exists to remove.
  const stderr = new StderrCapture();
  const connecting = connectWithTimeout(
    client,
    transport,
    containerStartTimeoutMs + connectTimeoutMs
  );
  stderr.attach(transport);

  // Attaching handlers here does not consume the rejection — `connecting`
  // stays rejected and the await below still sees it — it only records that
  // the race is over so the container poll can stop early, and keeps Node
  // from reporting an unhandled rejection in the window before that await.
  let connectSettled = false;
  const markSettled = (): void => {
    connectSettled = true;
  };
  connecting.then(markSettled, markSettled);

  let containerStartMs = 0;
  try {
    containerStartMs = await opts.sandbox.waitForContainerRunning(
      containerStartTimeoutMs,
      () => connectSettled
    );
  } catch (err) {
    try {
      await transport.close();
    } catch {
      // Already dead, or never started.
    }
    throw new ConnectorError(`${(err as Error).message}${stderr.suffix()}`);
  }

  // Only now does the target's own clock start. Everything above this line
  // was palar getting out of its own way.
  try {
    await withTimeout(connecting, connectTimeoutMs, `connect to "${server.name}" (stdio)`);
  } catch (err) {
    try {
      await transport.close();
    } catch {
      // Already dead, or never started.
    }
    // Re-wrapped rather than rethrown so the target's own explanation
    // travels with the failure all the way out to the report.
    throw new ConnectorError(`${(err as Error).message}${stderr.suffix()}`);
  }

  const pid = transport.pid;
  const sandbox = opts.sandbox;
  let closed = false;
  return {
    client,
    pid,
    transportKind: "stdio",
    containerStartMs,
    async close() {
      if (closed) return;
      closed = true;
      try {
        await withTimeout(transport.close(), 3_000, `close "${server.name}"`);
      } catch {
        // Graceful close didn't finish in time — fall through to the
        // unconditional kill below regardless of why.
      }
      // Kills the local `docker` CLI client, not the container itself —
      // sandbox.teardown() (docker rm -f) is the real backstop.
      if (pid !== null) forceKill(pid);
      await sandbox.teardown();
    },
  };
}
