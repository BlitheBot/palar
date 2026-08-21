/**
 * Unit tests for probe coverage and the exit-code rule it drives.
 *
 * This is the behaviour a CI gate depends on, so the cases below are the
 * ones where getting it wrong would be invisible: a run that learned
 * nothing but exits 0, and a run that learned something but fails.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { summarizeProbeCoverage } from "./coverage.js";
import type { LiveProbeResult, ProbeStatus } from "./types.js";

function probe(status: ProbeStatus): LiveProbeResult {
  return {
    toolName: "t",
    fieldPath: "f",
    kind: "command-injection",
    reason: "r",
    payload: "p",
    nonce: "n",
    argumentIssues: [],
    status,
    callback: null,
    callbackTimeoutMs: 4000,
    toolCall: { textPreview: "" },
    control: null,
  };
}

test("rejected and unconfirmed count as coverage", () => {
  // Neither is a clean bill of health, but both are real observations of a
  // payload that reached the field. They are what "palar looked" means.
  const c = summarizeProbeCoverage([probe("rejected"), probe("unconfirmed")]);
  assert.equal(c.exercised, 2);
  assert.equal(c.unexamined, 0);
  assert.equal(c.examinedNothing, false);
});

test("confirmed counts as coverage", () => {
  const c = summarizeProbeCoverage([probe("confirmed")]);
  assert.equal(c.exercised, 1);
  assert.equal(c.examinedNothing, false);
});

test("not-tested and inconclusive are both unexamined", () => {
  const c = summarizeProbeCoverage([probe("not-tested"), probe("inconclusive")]);
  assert.equal(c.exercised, 0);
  assert.equal(c.notTested, 1);
  assert.equal(c.inconclusive, 1);
  assert.equal(c.unexamined, 2);
  assert.equal(c.examinedNothing, true);
});

test("an all-inconclusive scan examined nothing", () => {
  // The playwright shape: every probe bounced because the tool could not
  // run in the container. Exiting 0 here would report a scan that tested
  // nothing as a scan that found nothing.
  const c = summarizeProbeCoverage([probe("inconclusive"), probe("inconclusive")]);
  assert.equal(c.examinedNothing, true);
});

test("one exercised probe among many unexamined is NOT a failure", () => {
  // The no-threshold decision, pinned. This run is mostly coverage gap and
  // says so loudly in its warning and headline, but it did learn something
  // — and picking the fraction at which it stops counting would be a magic
  // number in a CI gate.
  const c = summarizeProbeCoverage([
    probe("rejected"),
    probe("inconclusive"),
    probe("inconclusive"),
    probe("not-tested"),
    probe("inconclusive"),
  ]);
  assert.equal(c.exercised, 1);
  assert.equal(c.unexamined, 4);
  assert.equal(c.examinedNothing, false);
});

test("a scan with no probes at all does not claim to have examined nothing", () => {
  // A different event, already handled upstream by the never-reached and
  // no-tools branches. Reporting it here too would double-count it.
  const c = summarizeProbeCoverage([]);
  assert.equal(c.total, 0);
  assert.equal(c.examinedNothing, false);
});
