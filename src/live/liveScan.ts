/**
 * Orchestrates one live scan: connect to the real target, list its actual
 * tools, probe the ones that look injectable, and check description
 * poisoning against the live (not just static-file) content.
 *
 * Safety posture for stdio targets (see sandbox.ts for exactly what is and
 * isn't covered):
 *   - the target's declared command runs inside an ephemeral, network-
 *     restricted Docker container, mounted read-only, with dropped
 *     capabilities and resource limits — not directly on this host
 *   - the container's only permitted egress is to this scan's own oracle
 *     callback listener; everything else is rejected at the firewall,
 *     both forwarded traffic (DOCKER-USER) and host-destined traffic
 *     (INPUT) — the latter is what services listening on the host itself
 *     would otherwise be reachable through
 *   - the container has no working DNS resolver at all, so it cannot
 *     resolve arbitrary hostnames; the oracle callback works regardless
 *     because host.docker.internal is pinned in the container's /etc/hosts
 *   - the whole scan is bounded by a hard overall timeout, and the
 *     container/network/firewall rules are torn down unconditionally in
 *     `finally`, success, failure, or timeout; anything an earlier crashed
 *     run orphaned is reclaimed by the CLI's startup sweep
 * NOT covered: this is container isolation (Docker + iptables), not a VM
 * or gVisor — a kernel-level container escape isn't mitigated. See
 * README.md's "Live scanning" section for the full list of what's still
 * out of scope (concurrent-scan firewall races, oracle rate-limiting,
 * etc.). SSE targets have no local process to sandbox and are unaffected —
 * this module's safety posture for them is unchanged: a clean env is moot
 * (nothing is spawned) and only the overall timeout applies.
 */
import { CallbackOracle } from "./oracle.js";
import { connectLive, type LiveConnection } from "./connector.js";
import { TargetSandbox } from "./sandbox.js";
import {
  classifyExecutionAdjacentFields,
  detectPoisonedDescription,
  buildCommandInjectionPayload,
  buildSsrfPayload,
  buildProbeArguments,
  type LiveTool,
  type FieldProbeTarget,
} from "./probes.js";
import type { MCPServerConfig, MCPToolDefinition } from "../core/types.js";
import type {
  LiveAuditResult,
  LiveProbeResult,
  PoisoningLiveCheck,
  ToolCallCapture,
  ToolDriftEntry,
} from "./types.js";

export interface LiveScanOptions {
  /** Read-only container mount root for stdio targets — the target's own directory, not mcpguard's. */
  targetDir?: string;
  /** How long to wait for the connect/handshake, default 30000ms (see connector.ts). */
  connectTimeoutMs?: number;
  /** How long to wait for an oracle callback after each probe call, default 4000ms. */
  callbackTimeoutMs?: number;
  /**
   * Hard ceiling for the whole scan (connect + listTools + all probes),
   * default 60000ms. Must stay comfortably above connectTimeoutMs: this
   * deadline races the entire scan, so a smaller value here silently
   * preempts the connect timeout rather than adding to it. The default
   * leaves room for a worst-case 30s connect plus the ~11s of listTools
   * and probing measured against the vuln-server fixture.
   */
  overallTimeoutMs?: number;
  /**
   * Oracle bind host — only meaningful for SSE targets. For stdio targets
   * the oracle instead binds to whatever sandbox.ts's TargetSandbox decides
   * is actually reachable/bindable on this Docker backend (host loopback
   * on Docker Desktop, the sandbox network's gateway address on native
   * Linux Engine — see sandbox.ts's `oracleBindHost`); this option is
   * ignored in that case.
   */
  oracleHost?: string;
}

function captureToolResult(result: unknown): ToolCallCapture {
  const r = result as { isError?: boolean; content?: { type: string; text?: string }[] };
  const texts = Array.isArray(r.content)
    ? r.content
        .filter((c) => c.type === "text" && typeof c.text === "string")
        .map((c) => c.text as string)
    : [];
  const joined = texts.join("\n");
  return {
    isError: r.isError,
    textPreview: joined.length > 500 ? `${joined.slice(0, 500)}…` : joined,
  };
}

async function callToolSafely(
  connection: LiveConnection,
  toolName: string,
  args: Record<string, unknown>
): Promise<ToolCallCapture | { error: string }> {
  try {
    const result = await connection.client.callTool({ name: toolName, arguments: args });
    return captureToolResult(result);
  } catch (err) {
    return { error: (err as Error).message };
  }
}

async function runOneProbe(
  connection: LiveConnection,
  oracle: CallbackOracle,
  tool: LiveTool,
  target: FieldProbeTarget,
  callbackTimeoutMs: number
): Promise<LiveProbeResult> {
  const nonce = oracle.newNonce(`${tool.name}-${target.fieldPath}`);
  const callbackUrl = oracle.callbackUrl(nonce);
  const payload =
    target.kind === "ssrf"
      ? buildSsrfPayload(callbackUrl)
      : buildCommandInjectionPayload("127.0.0.1", callbackUrl);
  const args = buildProbeArguments(tool, target, payload);

  const toolCall = await callToolSafely(connection, tool.name, args);
  const callback = await oracle.waitForCallback(nonce, callbackTimeoutMs);

  return {
    toolName: tool.name,
    fieldPath: target.fieldPath,
    kind: target.kind,
    reason: target.reason,
    payload,
    nonce,
    status: callback ? "confirmed" : "unconfirmed",
    callback,
    callbackTimeoutMs,
    toolCall,
  };
}

async function runPoisoningCheck(
  connection: LiveConnection,
  tool: LiveTool,
  staticTools: Map<string, MCPToolDefinition>
): Promise<PoisoningLiveCheck | null> {
  const hit = detectPoisonedDescription(tool);
  if (!hit) return null;

  const staticDef = staticTools.get(tool.name);
  const liveDescriptionMatchesStatic =
    staticDef && typeof staticDef.description === "string"
      ? staticDef.description === tool.description
      : null;

  const properties = tool.inputSchema.properties ?? {};
  const args: Record<string, unknown> = {};
  for (const name of Object.keys(properties)) {
    args[name] = "This is a benign sentence for a live poisoning check. It has two sentences.";
  }

  const toolCall = await callToolSafely(connection, tool.name, args);

  return {
    toolName: tool.name,
    codePoints: hit.codePoints,
    liveDescriptionMatchesStatic,
    toolCall,
  };
}

export async function runLiveScan(
  server: MCPServerConfig,
  staticTools: { file: string; definition: MCPToolDefinition }[],
  opts: LiveScanOptions = {}
): Promise<LiveAuditResult> {
  const start = Date.now();
  const overallTimeoutMs = opts.overallTimeoutMs ?? 60_000;
  const callbackTimeoutMs = opts.callbackTimeoutMs ?? 4_000;
  const warnings: string[] = [];
  const errors: string[] = [];

  const isStdio = server.transport !== "sse";

  // A holder object, not bare `let`s: the setup below happens inside an
  // async closure past several `await`s, so TypeScript's control-flow
  // narrowing can't see that the assignments have happened by the time
  // `finally` runs — reading mutable properties sidesteps that (real, if
  // unrelated to the code's actual behavior) narrowing limitation.
  const holder: {
    connection: LiveConnection | null;
    sandbox: TargetSandbox | null;
    oracle: CallbackOracle | null;
  } = { connection: null, sandbox: null, oracle: null };

  const result: LiveAuditResult = {
    timestamp: new Date().toISOString(),
    serverName: server.name,
    transportKind: isStdio ? "stdio" : "sse",
    pid: null,
    connectDurationMs: 0,
    liveTools: [],
    toolDrift: [],
    probes: [],
    poisoningChecks: [],
    oracle: { baseUrl: "" },
    warnings,
    errors,
    durationMs: 0,
  };

  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  const overallDeadline = new Promise<never>((_, reject) => {
    deadlineTimer = setTimeout(() => {
      reject(new Error(`live scan exceeded overall timeout of ${overallTimeoutMs}ms`));
    }, overallTimeoutMs);
  });

  const work = (async () => {
    // Docker is mandatory for stdio: the sandbox (and the container network
    // it creates) has to exist before the oracle starts, because which
    // address the oracle can both bind to and be reached at is a property
    // of the detected Docker backend and that specific network (see
    // sandbox.ts / oracle.ts docstrings). SSE has no local process, so no
    // sandbox is created and the oracle keeps its original loopback/
    // opts.oracleHost behavior.
    let sandbox: TargetSandbox | null = null;
    if (isStdio) {
      sandbox = await TargetSandbox.create();
      holder.sandbox = sandbox;
    }

    const oracle = sandbox
      ? new CallbackOracle(sandbox.oracleBindHost, { advertisedHost: "host.docker.internal" })
      : new CallbackOracle(opts.oracleHost ?? "127.0.0.1");
    await oracle.start();
    holder.oracle = oracle;
    result.oracle = { baseUrl: oracle.baseUrl };

    if (sandbox) {
      await sandbox.installFirewall(oracle.port);
    }

    const connectStart = Date.now();
    const connection = await connectLive(server, {
      targetDir: opts.targetDir,
      connectTimeoutMs: opts.connectTimeoutMs,
      sandbox: sandbox ?? undefined,
    });
    holder.connection = connection;
    result.connectDurationMs = Date.now() - connectStart;
    result.pid = connection.pid;

    const listed = await connection.client.listTools();
    const liveTools = listed.tools as unknown as LiveTool[];
    result.liveTools = liveTools.map((t) => ({ name: t.name, description: t.description }));

    const staticByName = new Map(staticTools.map((t) => [t.definition.name, t.definition]));
    const liveNames = new Set(liveTools.map((t) => t.name));
    const toolDrift: ToolDriftEntry[] = [];
    for (const name of staticByName.keys()) {
      if (!liveNames.has(name)) toolDrift.push({ toolName: name, kind: "only-in-static-file" });
    }
    for (const name of liveNames) {
      if (!staticByName.has(name)) toolDrift.push({ toolName: name, kind: "only-in-live-server" });
    }
    result.toolDrift = toolDrift;

    for (const tool of liveTools) {
      const targets = classifyExecutionAdjacentFields(tool);
      for (const target of targets) {
        result.probes.push(await runOneProbe(connection, oracle, tool, target, callbackTimeoutMs));
      }
      const poisoning = await runPoisoningCheck(connection, tool, staticByName);
      if (poisoning) result.poisoningChecks.push(poisoning);
    }
  })();

  try {
    await Promise.race([work, overallDeadline]);
  } catch (err) {
    errors.push((err as Error).message);
  } finally {
    clearTimeout(deadlineTimer);
    if (holder.connection) {
      try {
        await holder.connection.close();
      } catch (err) {
        warnings.push(`failed to cleanly close target: ${(err as Error).message}`);
      }
    }
    if (holder.sandbox) {
      // Defensive and idempotent: connectLive() may have thrown before a
      // connection existed (e.g. the container never started), in which
      // case close() above never ran and never tore the sandbox down.
      // Also covers holder.connection.close() itself throwing before it
      // reached its own sandbox.teardown() call.
      await holder.sandbox.teardown();
    }
    if (holder.oracle) {
      await holder.oracle.stop();
    }
  }

  result.durationMs = Date.now() - start;
  return result;
}
