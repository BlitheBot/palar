/**
 * Live connector: actually spawns (stdio) or connects to (SSE) a discovered
 * MCP server and speaks the real protocol to it, using
 * @modelcontextprotocol/sdk's Client. This is the piece that did not exist
 * before this module — previously mcpguard only read the JSON files that
 * describe a server, never ran one.
 *
 * NOT sandboxing. See the module docstring in liveScan.ts for what
 * protections exist (clean-env construction, hard timeout, unconditional
 * kill) and what does not (no container, no gVisor, no filesystem or
 * network isolation — a malicious target can read this host's filesystem
 * or make arbitrary outbound network calls while it runs).
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { MCPServerConfig } from "../core/types.js";
import { buildCleanEnv } from "./env.js";

export interface LiveConnection {
  client: Client;
  /** Child process pid for stdio targets; null for SSE (no local process). */
  pid: number | null;
  transportKind: "stdio" | "sse";
  /** Graceful close, then an unconditional kill-by-pid backstop for stdio. */
  close(): Promise<void>;
}

export interface ConnectOptions {
  /** Working directory for a spawned stdio child (default: process.cwd()). */
  cwd?: string;
  /** Milliseconds to wait for the initial connect/handshake. */
  connectTimeoutMs?: number;
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

  const transport = new StdioClientTransport({
    command: server.command,
    args: server.args ?? [],
    // Deliberately NOT `...process.env` — see env.ts for exactly what this
    // does and does not guarantee about the child's final environment.
    env: buildCleanEnv(server.env),
    cwd: opts.cwd,
    stderr: "pipe",
  });

  await withTimeout(client.connect(transport), connectTimeoutMs, `connect to "${server.name}" (stdio)`);

  const pid = transport.pid;
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
      if (pid !== null) forceKill(pid);
    },
  };
}
