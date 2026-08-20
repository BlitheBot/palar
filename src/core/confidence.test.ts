/**
 * Guards on confidence: the axis that says how much of a finding palar
 * established, as distinct from how bad it would be.
 *
 * The load-bearing test in here is the last group. `any confirmed finding
 * yields grade F` is currently *also* true by arithmetic — a confirmed
 * finding is always `critical`, and 50 x 1.25 = 62.5 already clears the 60
 * points between F and D. That coincidence is exactly why the guarantee
 * needs its own test: it depends on three constants in three places, and
 * the day palar grows a confirmed class that is not critical (a confirmed
 * information disclosure at `high` scores 62, a solid D) a callback-proven
 * defect would start passing a gate, silently, with no test failing.
 *
 * So these assertions deliberately use severities the arithmetic would NOT
 * carry to F on its own. If someone reimplements the rule as a consequence
 * of the weights, these fail.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { computeScore, renderMarkdownReport } from "./compliance.js";
import type { AuditResult, Confidence, Finding, Severity } from "./types.js";

function mk(
  ruleId: string,
  severity: Severity,
  confidence: Confidence,
  n = 1
): Finding[] {
  return Array.from({ length: n }, () => ({
    ruleId,
    pillar: "schema-integrity" as const,
    severity,
    confidence,
    title: `${ruleId} on a field`,
    detail: "d",
    location: { file: "mcp.tools.json", jsonPath: 'tools["t"].inputSchema.properties.x' },
  }));
}

test("confidence scales the penalty without touching severity weights", () => {
  // Same severity, same rule, same count — only the claim differs.
  const confirmed = computeScore(mk("R", "medium", "confirmed"));
  const observed = computeScore(mk("R", "medium", "observed"));
  const hypothesized = computeScore(mk("R", "medium", "hypothesized"));

  assert.ok(
    confirmed.value < observed.value && observed.value < hypothesized.value,
    `expected confirmed < observed < hypothesized, got ` +
      `${confirmed.value} / ${observed.value} / ${hypothesized.value}`
  );
  // And the ordering is not a rescaling of severity: a HIGH hypothesis
  // still costs less than a MEDIUM observation. Severity alone would put
  // them the other way round, which is the flattening this axis exists to
  // undo.
  assert.ok(
    computeScore(mk("R", "high", "hypothesized")).value >
      computeScore(mk("R", "medium", "observed")).value
  );
});

test("a server with only unverified findings cannot reach F, at any count", () => {
  // The server-filesystem case, generalised. Eleven unverified `path`
  // fields put it at 20/F before this axis existed; a field-name heuristic
  // must be able to move a grade but never decide one.
  //
  // The large counts are the ones that matter. The 0.25 multiplier alone
  // does NOT bound this — per-rule dampening sums to 2*sqrt(n), so ~65
  // unverified mediums cross back into F on the arithmetic — which is why
  // the floor is a stated rule rather than a property of the weights.
  for (const n of [1, 5, 11, 20, 50, 65, 200, 5_000]) {
    const score = computeScore(mk("IV-001", "medium", "hypothesized", n));
    assert.notEqual(
      score.grade,
      "F",
      `${n} unverified mediums graded F at ${score.value}`
    );
  }
  // Across severities too: a pile of unverified criticals is still a pile
  // of guesses.
  for (const severity of ["critical", "high", "medium", "low"] as Severity[]) {
    assert.notEqual(computeScore(mk("IV-001", severity, "hypothesized", 100)).grade, "F");
  }
  // Several different unverified rules, not just repeats of one.
  assert.notEqual(
    computeScore([
      ...mk("IV-001", "medium", "hypothesized", 40),
      ...mk("IV-002", "low", "hypothesized", 40),
      ...mk("IV-004", "medium", "hypothesized", 40),
    ]).grade,
    "F"
  );
});

test("ONE observed finding lets a result reach F again", () => {
  // The floor is about inference, not about being lenient. A fact in the
  // file — a real credential, a real bidi override — is allowed to carry a
  // result to F on its own strength.
  const hypothesesOnly = computeScore(mk("IV-001", "medium", "hypothesized", 200));
  assert.equal(hypothesesOnly.grade, "D");

  const withOneFact = computeScore([
    ...mk("IV-001", "medium", "hypothesized", 200),
    ...mk("CR-001", "critical", "observed"),
  ]);
  assert.equal(withOneFact.grade, "F");
});

test("11 unverified mediums score exactly as the proposal modelled", () => {
  // Pinned rather than left to drift: this is the server-filesystem number
  // the scoring change was justified against.
  const score = computeScore(mk("IV-001", "medium", "hypothesized", 11));
  assert.equal(score.value, 80);
  assert.equal(score.grade, "B");
});

/**
 * The guarantee. Each of these uses a severity whose arithmetic alone would
 * NOT reach F, so they can only pass if the rule is stated rather than
 * derived.
 */
test("ANY confirmed finding yields grade F, whatever the arithmetic says", () => {
  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const score = computeScore(mk("IV-101", severity, "confirmed"));
    assert.equal(
      score.grade,
      "F",
      `a confirmed ${severity} finding graded ${score.grade} at ${score.value} — ` +
        `the "confirmed forces F" rule is not being applied independently of the weights`
    );
  }
});

test("a confirmed info finding — zero penalty — still grades F", () => {
  // The strongest form of the guarantee: severity weight for `info` is 0,
  // so the score is a perfect 100 and no multiplier can move it. If the
  // grade were derived from the number this would be an A.
  const score = computeScore(mk("IV-101", "info", "confirmed"));
  assert.equal(score.value, 100);
  assert.equal(score.grade, "F");
});

test("one confirmed finding among many clean ones still grades F", () => {
  const findings = [...mk("IV-001", "low", "hypothesized", 3), ...mk("IV-101", "low", "confirmed")];
  assert.equal(computeScore(findings).grade, "F");
});

test("the numeric score is NOT zeroed when the grade is forced", () => {
  // The number still ranks total exposure, which is information worth
  // keeping. desktop-commander (one confirmation) and vuln-server (two
  // confirmations plus six observed findings) are both F, and a reader
  // should still be able to see that one is far worse than the other.
  const one = computeScore(mk("IV-101", "critical", "confirmed"));
  const worse = computeScore([
    ...mk("IV-101", "critical", "confirmed"),
    ...mk("NB-003", "critical", "observed"),
    ...mk("CR-002", "high", "observed", 3),
  ]);
  assert.equal(one.grade, "F");
  assert.equal(worse.grade, "F");
  assert.ok(worse.value < one.value, "the forced grade flattened the numeric score");
});

test("no confirmed finding means the grade comes from the number as before", () => {
  // The rule must not leak: a high-scoring result with no confirmation is
  // graded normally.
  const clean = computeScore([]);
  assert.deepEqual(clean, { value: 100, grade: "A" });
  assert.equal(computeScore(mk("R", "medium", "observed")).grade, "A");
  // 100 - 50*0.6*(1 + 1/sqrt(2) + 1/sqrt(3)) = 31.5. Observed findings are
  // not floored, so this really is an F.
  assert.equal(computeScore(mk("R", "critical", "observed", 3)).grade, "F");
  assert.equal(computeScore(mk("R", "high", "observed")).grade, "B");
});

test("the report shows a confidence breakdown and explains a forced F", () => {
  const result: AuditResult = {
    timestamp: "2026-08-20T00:00:00.000Z",
    toolsScanned: 2,
    serversScanned: 1,
    findings: [...mk("IV-001", "medium", "hypothesized", 2), ...mk("IV-101", "critical", "confirmed")],
    score: computeScore([
      ...mk("IV-001", "medium", "hypothesized", 2),
      ...mk("IV-101", "critical", "confirmed"),
    ]),
    warnings: [],
  };
  const md = renderMarkdownReport(result);

  assert.match(md, /## Findings by confidence/);
  assert.match(md, /\| CONFIRMED \| 1 \|/);
  assert.match(md, /\| UNVERIFIED \| 2 \|/);
  assert.match(md, /\| OBSERVED \| 0 \|/);
  // Severity is still reported — confidence is additional, not a
  // replacement.
  assert.match(md, /## Findings by severity/);
  // A forced F says so, rather than leaving a reader to reconcile the
  // number with the letter.
  assert.match(md, /grade is F because something was CONFIRMED/);
  // And each finding carries both axes in its heading.
  assert.match(md, /### \[MEDIUM · UNVERIFIED\] IV-001/);
  assert.match(md, /### \[CRITICAL · CONFIRMED\] IV-101/);
});

test("a report with no confirmation does not claim a forced F", () => {
  const findings = mk("IV-001", "medium", "hypothesized", 2);
  const md = renderMarkdownReport({
    timestamp: "2026-08-20T00:00:00.000Z",
    toolsScanned: 1,
    serversScanned: 1,
    findings,
    score: computeScore(findings),
    warnings: [],
  });
  assert.match(md, /## Findings by confidence/);
  assert.doesNotMatch(md, /grade is F because/);
});
