/**
 * Live connector: actually spawns (stdio) or connects to (SSE) a discovered
 * MCP server and speaks the real protocol to it, using
 * @modelcontextprotocol/sdk's Client. This is the piece that did not exist
 * before this module — previously mcpguard only read the JSON files that
 * describe a server, never ran one.
 *
 * stdio targets run inside a Docker container (sandbox.ts), not directly
 * on this host — Docker is mandatory here, with no unsandboxed fallback.
 * What that does and doesn't cover is documented in sandbox.ts and
 * README.md's "Live scanning" section. SSE targets have no local process
 * to sandbox and are unaffected.
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { MCPServerConfig } from "../core/types.js";
import type { TargetSandbox } from "./sandbox.js";

export interface LiveConnection {
  client: Client;
  /** Child process pid for stdio targets; null for SSE (no local process). */
  pid: number | null;
  transportKind: "stdio" | "sse";
  /** Graceful close, then an unconditional kill-by-pid backstop for stdio. */
  close(): Promise<void>;
}

export interface ConnectOptions {
  /** Milliseconds to wait for the initial connect/handshake. */
  connectTimeoutMs?: number;
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
  const connectTimeoutMs = opts.connectTimeoutMs ?? 10_000;
  const client = new Client({ name: "mcpguard-live-scanner", version: "0.1.0" });

  if (server.transport === "sse") {
    if (!server.url) {
      throw new ConnectorError(
        `server "${server.name}" declares transport "sse" but no "url" — cannot connect`
      );
    }
    const transport: Transport = new SSEClientTransport(new URL(server.url));
    await withTimeout(client.connect(transport), connectTimeoutMs, `connect to "${server.name}" (SSE)`);
    return {
      client,
      pid: null,
      transportKind: "sse",
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

  await withTimeout(client.connect(transport), connectTimeoutMs, `connect to "${server.name}" (stdio)`);

  const pid = transport.pid;
  const sandbox = opts.sandbox;
  let closed = false;
  return {
    client,
    pid,
    transportKind: "stdio",
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
