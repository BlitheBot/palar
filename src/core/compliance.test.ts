import { test } from "node:test";
import assert from "node:assert/strict";
import { computeScore } from "./compliance.js";
import type { Finding, Severity } from "./types.js";

function mkFinding(ruleId: string, severity: Severity = "high"): Finding {
  return {
    ruleId,
    pillar: "schema-integrity",
    severity,
    title: "t",
    detail: "d",
    location: { file: "f.json" },
  };
}

test("zero findings scores exactly 100/A", () => {
  assert.deepEqual(computeScore([]), { value: 100, grade: "A" });
});

test("score is clamped to [0, 100] and never NaN", () => {
  const many = Array.from({ length: 50 }, (_, i) =>
    mkFinding(`R-${i}`, "critical")
  );
  const score = computeScore(many);
  assert.equal(score.value, 0);
  assert.equal(score.grade, "F");
  const scores = [
    computeScore([]),
    computeScore([mkFinding("X", "info")]),
    computeScore(many),
  ];
  for (const s of scores) {
    assert.ok(Number.isFinite(s.value));
    assert.ok(s.value >= 0 && s.value <= 100);
  }
});

test("info findings carry no penalty", () => {
  assert.equal(computeScore([mkFinding("X", "info")]).value, 100);
});

test("dampening: 3 highs from one rule score higher than from three rules", () => {
  const sameRule = computeScore([mkFinding("X"), mkFinding("X"), mkFinding("X")]);
  const threeRules = computeScore([mkFinding("X"), mkFinding("Y"), mkFinding("Z")]);
  // 100 - 30*(1 + 1/sqrt(2) + 1/sqrt(3)) rounds to 31; 100 - 3*30 = 10.
  assert.equal(sameRule.value, 31);
  assert.equal(threeRules.value, 10);
  assert.ok(sameRule.value > threeRules.value);
});

test("repeated low findings do not grind the score to zero", () => {
  const lows = Array.from({ length: 20 }, () => mkFinding("L", "low"));
  const score = computeScore(lows);
  assert.ok(score.value > 50, `expected > 50, got ${score.value}`);
});
