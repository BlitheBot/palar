/**
 * Unit tests for acknowledgements.
 *
 * The pair this file exists for is the escalation pair: an entry written
 * against `IV-001` must cover the `IV-101` that same finding becomes once
 * a callback proves it, AND must fail to cover it when `acceptsConfirmed`
 * is absent. Together those two are the whole design — aliasing makes the
 * feature usable across scan and live, and the flag stops aliasing from
 * silently widening into "config can bless proven defects".
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { applyAcknowledgements, type Acknowledgement } from "./acknowledgements.js";
import { escalateConfirmedFindings } from "../live/escalate.js";
import type { AuditResult, Finding } from "./types.js";
import type { LiveAuditResult, LiveProbeResult } from "../live/types.js";

const PATH = 'tools["start_process"].inputSchema.properties.command';

function staticFinding(over: Partial<Finding> = {}): Finding {
  return {
    ruleId: "IV-001",
    pillar: "schema-integrity",
    severity: "medium",
    confidence: "hypothesized",
    title: 'unconstrained execution-adjacent field "command"',
    detail: "hypothesis",
    location: { file: "mcp.tools.json", jsonPath: PATH },
    ...over,
  };
}

function resultOf(findings: Finding[]): AuditResult {
  return {
    timestamp: "2026-08-21T00:00:00.000Z",
    toolsScanned: 1,
    serversScanned: 1,
    findings,
    score: { value: 40, grade: "D" },
    warnings: [],
  };
}

function ack(over: Partial<Acknowledgement> = {}): Acknowledgement {
  return {
    ruleId: "IV-001",
    jsonPath: PATH,
    reason: "desktop-commander is a shell tool; execution is the product.",
    added: "2026-08-01",
    ...over,
  };
}

/** A confirmed probe on the same field, as liveScan would produce it. */
function confirmedProbe(): LiveProbeResult {
  return {
    toolName: "start_process",
    fieldPath: "command",
    kind: "command-injection",
    reason: "matched an execution-adjacent keyword",
    payload: "127.0.0.1; curl http://oracle/abc",
    nonce: "nonce-1",
    argumentIssues: [],
    status: "confirmed",
    callback: {
      nonce: "nonce-1",
      receivedAt: "2026-08-21T00:00:01.000Z",
      remoteAddress: "172.18.0.2",
      method: "GET",
      path: "/cb/nonce-1",
    },
    callbackTimeoutMs: 4000,
    toolCall: { isError: false, textPreview: "" },
    control: null,
  };
}

function liveResultWith(probe: LiveProbeResult): LiveAuditResult {
  return {
    timestamp: "2026-08-21T00:00:00.000Z",
    serverName: "desktop-commander",
    transportKind: "stdio",
    payloadEligibility: { eligible: true, sandboxed: true, kind: "stdio" },
    outcome: "probed",
    unreachable: null,
    pid: 1,
    sandboxSetupMs: 0,
    containerStartMs: 0,
    connectDurationMs: 1,
    liveTools: [],
    toolDrift: [],
    probes: [probe],
    poisoningChecks: [],
    oracle: { baseUrl: "http://127.0.0.1:1" },
    warnings: [],
    errors: [],
    durationMs: 1,
  };
}

// ---------------------------------------------------------------------------
// THE PAIR.
// ---------------------------------------------------------------------------

test("an IV-001 ack covers the IV-101 the same finding becomes after escalation", () => {
  // The motivating case end to end: a static hypothesis is acknowledged,
  // then a live run proves it and rewrites its ruleId. The acknowledgement
  // has to survive that, or it stops working at the exact moment the
  // finding it describes becomes most important.
  const escalated = escalateConfirmedFindings(resultOf([staticFinding()]), [
    liveResultWith(confirmedProbe()),
  ]);
  const confirmed = escalated.findings.find((f) => f.location.jsonPath === PATH)!;
  assert.equal(confirmed.ruleId, "IV-101", "precondition: escalation rewrote the id");
  assert.equal(confirmed.confidence, "confirmed");
  assert.deepEqual(confirmed.supersedes, ["IV-001"], "precondition: provenance recorded");

  const outcome = applyAcknowledgements(escalated, [
    ack({ acceptsConfirmed: true, expires: "2027-01-01" }),
  ]);

  const marked = outcome.result.findings.find((f) => f.location.jsonPath === PATH)!;
  assert.ok(marked.accepted, "IV-001 ack should cover the escalated IV-101");
  assert.equal(marked.accepted!.acceptsConfirmed, true);
  assert.equal(outcome.unmatched.length, 0);
  assert.equal(outcome.refusals.length, 0);
});

test("the same IV-001 ack does NOT cover it without acceptsConfirmed", () => {
  // The other half. Aliasing is what makes the entry keep matching; this
  // flag is what stops the match from silently becoming permission to
  // accept a callback-proven defect the author never considered.
  const escalated = escalateConfirmedFindings(resultOf([staticFinding()]), [
    liveResultWith(confirmedProbe()),
  ]);

  const outcome = applyAcknowledgements(escalated, [ack()]);

  const marked = outcome.result.findings.find((f) => f.location.jsonPath === PATH)!;
  assert.equal(marked.accepted, undefined, "must not be accepted");
  assert.equal(outcome.accepted.length, 0);
  assert.equal(outcome.refusals.length, 1);
  assert.match(outcome.refusals[0]!.reason, /acceptsConfirmed/);
  // Matched-but-refused is not stale: the entry points at something real.
  assert.equal(outcome.unmatched.length, 0);
});

// ---------------------------------------------------------------------------
// Matching and identity.
// ---------------------------------------------------------------------------

test("an ack covers a plain static finding", () => {
  const outcome = applyAcknowledgements(resultOf([staticFinding()]), [ack()]);
  assert.ok(outcome.result.findings[0]!.accepted);
  assert.equal(outcome.result.findings[0]!.accepted!.reason, ack().reason);
});

test("a different jsonPath does not match", () => {
  const outcome = applyAcknowledgements(resultOf([staticFinding()]), [
    ack({ jsonPath: 'tools["other"].inputSchema.properties.command' }),
  ]);
  assert.equal(outcome.result.findings[0]!.accepted, undefined);
  assert.equal(outcome.unmatched.length, 1);
});

test("file narrows when supplied and is ignored when absent", () => {
  const wrongFile = applyAcknowledgements(resultOf([staticFinding()]), [
    ack({ file: "other.json" }),
  ]);
  assert.equal(wrongFile.result.findings[0]!.accepted, undefined);

  const rightFile = applyAcknowledgements(resultOf([staticFinding()]), [
    ack({ file: "mcp.tools.json" }),
  ]);
  assert.ok(rightFile.result.findings[0]!.accepted);
});

test("acceptance never touches the score, grade, severity or confidence", () => {
  // The single most important invariant. Acceptance is a statement about
  // the build, not about the target; if it moved the number, a project
  // could reach 100/A by editing its own config.
  const before = resultOf([staticFinding({ severity: "critical" })]);
  const outcome = applyAcknowledgements(before, [ack()]);
  assert.deepEqual(outcome.result.score, before.score);
  assert.equal(outcome.result.findings.length, before.findings.length);
  assert.equal(outcome.result.findings[0]!.severity, "critical");
  assert.equal(outcome.result.findings[0]!.confidence, "hypothesized");
});

// ---------------------------------------------------------------------------
// Expiry and rot.
// ---------------------------------------------------------------------------

test("an expired ack stops applying and says the acceptance lapsed", () => {
  const outcome = applyAcknowledgements(
    resultOf([staticFinding()]),
    [ack({ expires: "2026-08-10" })],
    { now: new Date("2026-08-21T00:00:00Z") }
  );
  assert.equal(outcome.result.findings[0]!.accepted, undefined);
  assert.equal(outcome.refusals.length, 1);
  assert.match(outcome.refusals[0]!.reason, /expired on 2026-08-10/);
  assert.match(outcome.refusals[0]!.reason, /not a new problem/);
});

test("an ack expiring soon warns before it lapses", () => {
  const outcome = applyAcknowledgements(
    resultOf([staticFinding()]),
    [ack({ expires: "2026-08-28" })],
    { now: new Date("2026-08-21T00:00:00Z") }
  );
  assert.ok(outcome.result.findings[0]!.accepted, "still applies until it lapses");
  assert.equal(outcome.warnings.length, 1);
  assert.match(outcome.warnings[0]!, /expires in 7 day\(s\)/);
});

test("an old ack with no expiry warns about rot", () => {
  const outcome = applyAcknowledgements(
    resultOf([staticFinding()]),
    [ack({ added: "2026-01-01" })],
    { now: new Date("2026-08-21T00:00:00Z") }
  );
  assert.ok(outcome.result.findings[0]!.accepted, "still applies — visible, not fatal");
  assert.equal(outcome.warnings.length, 1);
  assert.match(outcome.warnings[0]!, /has no "expires"/);
});

test("a recent ack with no expiry is quiet", () => {
  const outcome = applyAcknowledgements(
    resultOf([staticFinding()]),
    [ack({ added: "2026-08-01" })],
    { now: new Date("2026-08-21T00:00:00Z") }
  );
  assert.deepEqual(outcome.warnings, []);
});

// ---------------------------------------------------------------------------
// Unmatched: fixed vs moved, and mode-aware quieting.
// ---------------------------------------------------------------------------

test("an unmatched ack whose finding vanished is reported with no move hint", () => {
  const outcome = applyAcknowledgements(resultOf([]), [ack()]);
  assert.equal(outcome.unmatched.length, 1);
  assert.equal(outcome.unmatched[0]!.possibleMove, undefined);
});

test("an unmatched ack detects a MOVED finding (the renamed-tool case)", () => {
  // A renamed tool moves every jsonPath beneath it at once, so "the ack
  // stopped matching" usually means the defect is still there under a new
  // name rather than that somebody fixed it.
  const renamed = staticFinding({
    location: {
      file: "mcp.tools.json",
      jsonPath: 'tools["startProcess"].inputSchema.properties.command',
    },
  });
  const outcome = applyAcknowledgements(resultOf([renamed]), [ack()]);
  assert.equal(outcome.unmatched.length, 1);
  assert.equal(
    outcome.unmatched[0]!.possibleMove?.jsonPath,
    'tools["startProcess"].inputSchema.properties.command'
  );
});

test("a live-only rule id is not reported as stale during a static run", () => {
  // IV-101 cannot exist before escalation. Warning about it on every
  // `palar scan` would train people to ignore the warning, which destroys
  // the one mechanism that catches genuinely rotten entries.
  const entry = ack({ ruleId: "IV-101", acceptsConfirmed: true, expires: "2027-01-01" });
  const quiet = applyAcknowledgements(resultOf([]), [entry], { live: false });
  assert.equal(quiet.unmatched.length, 0);

  const loud = applyAcknowledgements(resultOf([]), [entry], { live: true });
  assert.equal(loud.unmatched.length, 1);
});

test("a non-live rule id IS reported as stale during a static run", () => {
  const quiet = applyAcknowledgements(resultOf([]), [ack({ ruleId: "CR-003" })], {
    live: false,
  });
  assert.equal(quiet.unmatched.length, 1);
});

test("a sibling instance of a repeated rule is NOT reported as a move", () => {
  // NB-004 fires once per private host. An entry for a host that was
  // deleted must not point at a DIFFERENT host and call it a move — that
  // turns the hint into noise on exactly the rules that repeat.
  const other: Finding = {
    ruleId: "NB-004",
    pillar: "network-boundaries",
    severity: "high",
    confidence: "observed",
    title: "exposes private-network host",
    detail: "d",
    location: {
      file: "mcp.server.json",
      jsonPath: 'servers["srv"].network.exposedHosts["169.254.169.254"]',
    },
  };
  const outcome = applyAcknowledgements(resultOf([other]), [
    ack({
      ruleId: "NB-004",
      jsonPath: 'servers["srv"].network.exposedHosts["192.0.2.1"]',
    }),
  ]);
  assert.equal(outcome.unmatched.length, 1);
  assert.equal(outcome.unmatched[0]!.possibleMove, undefined, "sibling is not a move");
});

test("a renamed SERVER is reported as a move", () => {
  const renamed: Finding = {
    ruleId: "NB-003",
    pillar: "network-boundaries",
    severity: "critical",
    confidence: "observed",
    title: "exposes loopback",
    detail: "d",
    location: {
      file: "mcp.server.json",
      jsonPath: 'servers["renamed"].network.exposedHosts["127.0.0.1"]',
    },
  };
  const outcome = applyAcknowledgements(resultOf([renamed]), [
    ack({
      ruleId: "NB-003",
      jsonPath: 'servers["original"].network.exposedHosts["127.0.0.1"]',
    }),
  ]);
  assert.equal(outcome.unmatched[0]!.possibleMove?.jsonPath, renamed.location.jsonPath);
});
