/**
 * Orchestrates one live scan: connect to the real target, list its actual
 * tools, probe the ones that look injectable, and check description
 * poisoning against the live (not just static-file) content.
 *
 * Safety posture for this pass (deliberately not full sandboxing — see
 * connector.ts / env.ts docstrings for exactly what is and isn't covered):
 *   - the target's environment is built explicitly, not inherited from
 *     mcpguard's own process (env.ts)
 *   - the whole scan is bounded by a hard overall timeout
 *   - the target's child process is killed unconditionally in `finally`,
 *     success, failure, or timeout
 * NOT covered: filesystem isolation, network isolation, resource limits.
 * The target runs directly on this host with the ability to read this
 * filesystem and make arbitrary outbound network calls for the duration of
 * the scan. Real isolation (containers or gVisor) is a separate, larger
 * piece of work and a hard requirement before running this against any
 * third-party or client server.
 */
import { CallbackOracle } from "./oracle.js";
import { connectLive, type LiveConnection } from "./connector.js";
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
  cwd?: string;
  connectTimeoutMs?: number;
  /** How long to wait for an oracle callback after each probe call, default 4000ms. */
  callbackTimeoutMs?: number;
  /** Hard ceiling for the whole scan (connect + listTools + all probes), default 30000ms. */
  overallTimeoutMs?: number;
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
  const overallTimeoutMs = opts.overallTimeoutMs ?? 30_000;
  const callbackTimeoutMs = opts.callbackTimeoutMs ?? 4_000;
  const warnings: string[] = [];
  const errors: string[] = [];

  const oracle = new CallbackOracle(opts.oracleHost ?? "127.0.0.1");
  await oracle.start();

  // A holder object, not a bare `let`: the connect step happens inside an
  // async closure past an `await`, so TypeScript's control-flow narrowing
  // can't see that the assignment below has happened by the time `finally`
  // runs — reading a mutable property sidesteps that (real, if unrelated to
  // the code's actual behavior) narrowing limitation.
  const holder: { connection: LiveConnection | null } = { connection: null };

  const result: LiveAuditResult = {
    timestamp: new Date().toISOString(),
    serverName: server.name,
    transportKind: server.transport === "sse" ? "sse" : "stdio",
    pid: null,
    connectDurationMs: 0,
    liveTools: [],
    toolDrift: [],
    probes: [],
    poisoningChecks: [],
    oracle: { baseUrl: oracle.baseUrl },
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
    const connectStart = Date.now();
    const connection = await connectLive(server, {
      cwd: opts.cwd,
      connectTimeoutMs: opts.connectTimeoutMs,
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
    await oracle.stop();
  }

  result.durationMs = Date.now() - start;
  return result;
}
