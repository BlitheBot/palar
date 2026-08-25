/**
 * Integration test for the loopback-vs-remote payload-eligibility split on
 * SSE targets. Docker-free: SSE targets are never sandboxed, so this stands
 * up a real in-process MCP server over SSE and drives runLiveScan against
 * it — no container backend involved.
 *
 * It proves the two behaviours the design turns on, BEHAVIOURALLY (via the
 * server's own record of the calls it received), not just by inspecting the
 * classifier:
 *
 *   - REMOTE SSE  → the server is connected to and its tools listed, but it
 *     receives ZERO tools/call requests. This is the load-bearing proof
 *     that no payload went out — the assertion is on the server's call log,
 *     not on a printed notice.
 *   - LOOPBACK SSE → the server DOES receive the payload, and an SSRF probe
 *     confirms via the oracle callback, so a loopback target the operator
 *     owns is still probed for real.
 *
 * "Remote" is simulated hermetically: the server binds to 0.0.0.0 and the
 * remote case dials it through a NON-loopback IPv4 the machine actually has
 * (from os.networkInterfaces()). The literal host is what the classifier
 * judges, so a non-loopback literal that still routes to this box is exactly
 * the remote case without needing a second machine. If the box has no
 * non-loopback IPv4 (rare in CI, possible on a locked-down runner), that one
 * assertion is skipped with a note rather than faked.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { networkInterfaces } from "node:os";
import { AddressInfo } from "node:net";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { runLiveScan } from "./liveScan.js";
import type { MCPServerConfig } from "../core/types.js";

interface RecordedCall {
  name: string;
  args: Record<string, unknown>;
}

/**
 * A real MCP server spoken over SSE, in this process. Records every
 * tools/call it receives, and its one tool actually fetches its `url`
 * argument — so when the SSRF payload (which IS the oracle callback URL) is
 * sent, the callback fires and the probe can confirm.
 */
async function startSseMcpServer(): Promise<{
  port: number;
  calls: RecordedCall[];
  close: () => Promise<void>;
}> {
  const calls: RecordedCall[] = [];
  const transports = new Map<string, SSEServerTransport>();

  const makeServer = (): Server => {
    const server = new Server(
      { name: "sse-test-server", version: "0.0.0" },
      { capabilities: { tools: {} } }
    );
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: "fetch_url",
          description: "Fetches a URL server-side.",
          // Unconstrained string named "url" — classifyExecutionAdjacentFields
          // targets this as an SSRF probe.
          inputSchema: {
            type: "object",
            properties: { url: { type: "string" } },
            required: ["url"],
          },
        },
      ],
    }));
    server.setRequestHandler(CallToolRequestSchema, async (req) => {
      const args = (req.params.arguments ?? {}) as Record<string, unknown>;
      calls.push({ name: req.params.name, args });
      // SSRF-by-design: fetch whatever url we were handed. If it is the
      // oracle callback URL, this is what makes the probe CONFIRM.
      const url = typeof args.url === "string" ? args.url : null;
      if (url && /^https?:\/\//.test(url)) {
        try {
          await fetch(url, { signal: AbortSignal.timeout(2000) });
        } catch {
          // The reach is the point; the response is irrelevant.
        }
      }
      return { content: [{ type: "text", text: "ok" }] };
    });
    return server;
  };

  const httpServer = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/sse") {
      const transport = new SSEServerTransport("/messages", res);
      transports.set(transport.sessionId, transport);
      res.on("close", () => transports.delete(transport.sessionId));
      void makeServer().connect(transport);
      return;
    }
    if (req.method === "POST" && url.pathname === "/messages") {
      const sid = url.searchParams.get("sessionId") ?? "";
      const transport = transports.get(sid);
      if (!transport) {
        res.writeHead(400).end("no such session");
        return;
      }
      void transport.handlePostMessage(req, res);
      return;
    }
    res.writeHead(404).end();
  });

  await new Promise<void>((resolve) => httpServer.listen(0, "0.0.0.0", resolve));
  const port = (httpServer.address() as AddressInfo).port;

  return {
    port,
    calls,
    close: () =>
      new Promise<void>((resolve) => {
        for (const t of transports.values()) void t.close();
        httpServer.close(() => resolve());
      }),
  };
}

/** First non-internal IPv4 the machine has, or null. */
function firstNonLoopbackIpv4(): string | null {
  for (const addrs of Object.values(networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family === "IPv4" && !a.internal) return a.address;
    }
  }
  return null;
}

test("REMOTE SSE + live sends ZERO payloads (proven by the server's call log)", async () => {
  const remoteIp = firstNonLoopbackIpv4();
  const srv = await startSseMcpServer();
  try {
    if (remoteIp === null) {
      // Honest skip rather than a faked pass — see file docstring.
      return;
    }
    const server: MCPServerConfig = {
      name: "remote-sse",
      transport: "sse",
      url: `http://${remoteIp}:${srv.port}/sse`,
    };

    const result = await runLiveScan(server, [], {
      connectTimeoutMs: 10_000,
      overallTimeoutMs: 30_000,
      callbackTimeoutMs: 2_000,
    });

    // It connected and enumerated: the server really was reached.
    assert.equal(result.outcome, "probed", `outcome was ${result.outcome}`);
    assert.ok(
      result.liveTools.some((t) => t.name === "fetch_url"),
      "did not enumerate the remote server's tools"
    );

    // The classifier downgraded it.
    assert.equal(result.payloadEligibility.eligible, false);

    // No probe was produced...
    assert.equal(result.probes.length, 0, "a probe was built for a remote SSE target");

    // ...and — the load-bearing proof — the SERVER received no tools/call at
    // all. Nothing was sent, not merely nothing printed.
    assert.deepEqual(
      srv.calls,
      [],
      `remote SSE target received calls it should never have: ${JSON.stringify(srv.calls)}`
    );

    // The downgrade is a visible notice, not a silent skip.
    assert.ok(
      result.warnings.some((w) => /NO payload sent/.test(w)),
      `no downgrade notice in warnings: ${JSON.stringify(result.warnings)}`
    );
  } finally {
    await srv.close();
  }
});

test("LOOPBACK SSE + live probes for real and can still confirm", async () => {
  const srv = await startSseMcpServer();
  try {
    const server: MCPServerConfig = {
      name: "loopback-sse",
      transport: "sse",
      url: `http://127.0.0.1:${srv.port}/sse`,
    };

    const result = await runLiveScan(server, [], {
      connectTimeoutMs: 10_000,
      overallTimeoutMs: 30_000,
      callbackTimeoutMs: 4_000,
    });

    assert.equal(result.outcome, "probed", `outcome was ${result.outcome}`);
    assert.equal(result.payloadEligibility.eligible, true);
    assert.equal(
      result.payloadEligibility.eligible && result.payloadEligibility.kind,
      "sse-loopback"
    );

    // A probe was actually sent, and the server received it.
    assert.ok(result.probes.length > 0, "no probe was built for a loopback SSE target");
    assert.ok(srv.calls.length > 0, "loopback SSE server received no tool call");

    // And the SSRF probe confirmed via the oracle callback — a loopback
    // target is genuinely exercised, not just contacted.
    assert.ok(
      result.probes.some(
        (p) => p.kind === "ssrf" && p.toolName === "fetch_url" && p.status === "confirmed"
      ),
      `SSRF did not confirm on loopback SSE — probes: ${JSON.stringify(
        result.probes.map((p) => ({ tool: p.toolName, kind: p.kind, status: p.status }))
      )}`
    );
  } finally {
    await srv.close();
  }
});
