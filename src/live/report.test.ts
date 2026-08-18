/**
 * Guards the reporting constraints around the "rejected" status:
 *   - severity is never changed on account of a rejected probe
 *   - a rejected finding is never suppressed
 *   - a probe that NEVER RAN cannot be reported as rejected; its static
 *     finding stays in STATIC-ONLY untouched
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { renderLiveMarkdownReport } from "./report.js";
import type { AuditResult, Finding } from "../core/types.js";
import type { LiveAuditResult, LiveProbeResult } from "./types.js";

function finding(toolName: string, field: string): Finding {
  return {
    ruleId: "IV-001",
    pillar: "schema-integrity",
    severity: "high",
    title: `unconstrained execution-adjacent field "${field}"`,
    detail: "no pattern/enum/format constraint",
    location: { file: "mcp.tools.json", jsonPath: `tools["${toolName}"].inputSchema.properties.${field}` },
  };
}

function staticResult(findings: Finding[]): AuditResult {
  return {
    timestamp: "2026-08-18T00:00:00.000Z",
    toolsScanned: findings.length,
    serversScanned: 1,
    findings,
    score: { value: 0, grade: "F" },
    warnings: [],
  };
}

function probe(over: Partial<LiveProbeResult>): LiveProbeResult {
  return {
    toolName: "read_file",
    fieldPath: "path",
    kind: "command-injection",
    reason: "matched an execution-adjacent keyword",
    payload: "127.0.0.1; curl ...",
    nonce: "n1",
    status: "rejected",
    callback: null,
    callbackTimeoutMs: 4000,
    toolCall: { isError: true, textPreview: "Parent directory does not exist: /tmp/127.0.0.1" },
    ...over,
  };
}

function liveResult(probes: LiveProbeResult[]): LiveAuditResult {
  return {
    timestamp: "2026-08-18T00:00:00.000Z",
    serverName: "server-filesystem",
    transportKind: "stdio",
    pid: 1234,
    connectDurationMs: 100,
    liveTools: [],
    toolDrift: [],
    probes,
    poisoningChecks: [],
    oracle: { baseUrl: "http://127.0.0.1:9999" },
    warnings: [],
    errors: [],
    durationMs: 200,
  };
}

test("a rejected probe renders in its own section and keeps the static severity", () => {
  const md = renderLiveMarkdownReport(staticResult([finding("read_file", "path")]), liveResult([probe({})]));

  assert.match(md, /## ATTEMPTED — REJECTED BY TARGET/);
  assert.match(md, /\[ATTEMPTED — REJECTED BY TARGET\] read_file\.path/);
  // The finding is not suppressed, and its severity is untouched.
  assert.match(md, /1 probe\(s\) that the target ANSWERED WITH AN ERROR/);
  assert.doesNotMatch(md, /\bMEDIUM\b|\bLOW\b|downgrad/i);
});

test("a rejected probe quotes the target's own error text verbatim", () => {
  const md = renderLiveMarkdownReport(
    staticResult([]),
    liveResult([
      probe({
        toolName: "list_directory_with_sizes",
        toolCall: {
          isError: true,
          textPreview: "MCP error -32602: Input validation error: Invalid arguments",
        },
      }),
    ])
  );
  // The text is what distinguishes an argument-validation bounce from a
  // handler-level refusal, so it must survive into the report intact.
  assert.match(md, /Rejected with \(isError=true\):\*\* MCP error -32602: Input validation error/);
});

test("a probe that never ran is NOT rejected — its static finding stays in STATIC-ONLY", () => {
  // No probes at all (e.g. the server never connected). Absence of a probe
  // must never be read as evidence of safety.
  const md = renderLiveMarkdownReport(staticResult([finding("read_file", "path")]), liveResult([]));

  assert.match(md, /## ATTEMPTED — REJECTED BY TARGET\n\n0 probe\(s\)/);
  assert.match(md, /## STATIC-ONLY[^]*\[HIGH\] IV-001/);
  assert.doesNotMatch(md, /\[ATTEMPTED — REJECTED BY TARGET\] read_file\.path/);
});

test("a confirmed probe with isError=true renders as CONFIRMED, never rejected", () => {
  const md = renderLiveMarkdownReport(
    staticResult([]),
    liveResult([
      probe({
        status: "confirmed",
        callback: {
          nonce: "n1",
          receivedAt: "2026-08-18T00:00:01.000Z",
          remoteAddress: "172.18.0.2",
          method: "GET",
          path: "/cb/n1",
        },
        toolCall: { isError: true, textPreview: "exit status 7" },
      }),
    ])
  );
  assert.match(md, /\[CONFIRMED\] read_file\.path/);
  assert.doesNotMatch(md, /\[ATTEMPTED — REJECTED BY TARGET\] read_file\.path/);
  assert.match(md, /## ATTEMPTED — REJECTED BY TARGET\n\n0 probe\(s\)/);
});

test("rejected and unconfirmed are reported separately, not merged", () => {
  const md = renderLiveMarkdownReport(
    staticResult([]),
    liveResult([
      probe({ toolName: "read_file" }),
      probe({
        toolName: "search_nodes",
        fieldPath: "query",
        status: "unconfirmed",
        toolCall: { textPreview: '{"entities": []}' },
      }),
    ])
  );
  assert.match(md, /## ATTEMPTED — REJECTED BY TARGET\n\n1 probe\(s\)/);
  assert.match(md, /## ATTEMPTED — UNCONFIRMED\n\n1 probe\(s\)/);
  assert.match(md, /\[ATTEMPTED — REJECTED BY TARGET\] read_file\.path/);
  assert.match(md, /\[ATTEMPTED — UNCONFIRMED\] search_nodes\.query/);
});
