import { test } from "node:test";
import assert from "node:assert/strict";
import { computeScore } from "./compliance.js";
import type {
  Finding,
  MCPServerConfig,
  MCPToolDefinition,
  Severity,
} from "./types.js";
import { inputValidationRule } from "../rules/input-validation.js";
import { schemaValidationRule } from "../rules/schema-validation.js";
import { descriptionHygieneRule } from "../rules/description-hygiene.js";
import { textSanitizerRule } from "../rules/text-sanitizer.js";
import { credentialScannerToolRule } from "../rules/credential-scanner.js";
import { networkBoundsRule } from "../rules/network-bounds.js";

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

/*
 * Compliance-reference mappings are load-bearing: they are what a report tells
 * a reader their findings mean under an external standard, so a silent edit is
 * a correctness bug, not a cosmetic one. These pin the exact strings that reach
 * a rendered report. The OWASP MCP Top 10 is a Phase 3 beta — if its category
 * names or IDs change upstream, update these deliberately.
 */

const ruleCtx = { file: "test.json" };

/** Minimal inputs that each fire exactly one rule, to read its refs back. */
const MAPPINGS: Array<{
  label: string;
  refs: string[];
  run: () => Finding[];
}> = [
  {
    label: "input-validation",
    refs: ["OWASP MCP05:2025 - Command Injection & Execution"],
    run: () =>
      inputValidationRule.check(
        {
          name: "deploy",
          inputSchema: { type: "object", properties: { command: { type: "string" } } },
        } as unknown as MCPToolDefinition,
        ruleCtx
      ),
  },
  {
    label: "schema-validation",
    refs: ["OWASP MCP05:2025 - Command Injection & Execution"],
    run: () =>
      schemaValidationRule.check(
        {
          name: "t",
          inputSchema: { type: "object", properties: { a: { type: "bogus" } } },
        } as unknown as MCPToolDefinition,
        ruleCtx
      ),
  },
  {
    label: "description-hygiene",
    refs: ["OWASP MCP03:2025 - Tool Poisoning"],
    run: () =>
      descriptionHygieneRule.check(
        { name: "t" } as unknown as MCPToolDefinition,
        ruleCtx
      ),
  },
  {
    label: "text-sanitizer",
    refs: ["OWASP MCP03:2025 - Tool Poisoning"],
    run: () =>
      textSanitizerRule.check(
        {
          name: "t",
          // Zero-width space, written as an escape so it stays visible in source.
          description: "hello\u200Bworld",
        } as unknown as MCPToolDefinition,
        ruleCtx
      ),
  },
  {
    label: "credential-scanner",
    refs: ["OWASP MCP01:2025 - Token Mismanagement & Secret Exposure"],
    run: () =>
      credentialScannerToolRule.check(
        {
          name: "t",
          description: "key AKIAABCDEFGHIJKLMNOP",
        } as unknown as MCPToolDefinition,
        ruleCtx
      ),
  },
];

for (const { label, refs, run } of MAPPINGS) {
  test(`${label} findings cite exactly ${refs[0]}`, () => {
    const findings = run();
    assert.ok(findings.length > 0, `${label} fixture fired no finding`);
    for (const finding of findings) {
      assert.deepEqual(
        finding.complianceRefs,
        refs,
        `${label} ${finding.ruleId} drifted from its pinned compliance reference`
      );
    }
  });
}

test("network-bounds stays an internal category, not an OWASP citation", () => {
  // No OWASP MCP Top 10 entry covers SSRF; an "OWASP" ref here would claim an
  // alignment that does not exist.
  const findings = networkBoundsRule.check(
    { name: "srv" } as unknown as MCPServerConfig,
    ruleCtx
  );
  assert.ok(findings.length > 0);
  for (const finding of findings) {
    assert.deepEqual(finding.complianceRefs, ["mcpguard:SSRF"]);
  }
});
