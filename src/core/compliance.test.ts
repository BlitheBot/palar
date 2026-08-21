import { test } from "node:test";
import assert from "node:assert/strict";
import { computeScore, renderMarkdownReport } from "./compliance.js";
import type {
  AuditResult,
  Confidence,
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

function mkFinding(
  ruleId: string,
  severity: Severity = "high",
  confidence: Confidence = "observed"
): Finding {
  return {
    ruleId,
    pillar: "schema-integrity",
    severity,
    confidence,
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
  // Weight per finding is high(30) x observed(0.6) = 18.
  // 100 - 18*(1 + 1/sqrt(2) + 1/sqrt(3)) rounds to 59; 100 - 3*18 = 46.
  assert.equal(sameRule.value, 59);
  assert.equal(threeRules.value, 46);
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
    // DH-001 is pinned SEPARATELY and deliberately does not cite Tool
    // Poisoning: it reports that a description is long, which is not evidence
    // of injected instructions. DH-002 and the TS-* rules test for those.
    label: "description-hygiene DH-001",
    refs: ["palar:context-budget"],
    run: () =>
      descriptionHygieneRule.check(
        { name: "t", description: "x".repeat(4100) } as unknown as MCPToolDefinition,
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
  //
  // The fixture DECLARES a posture: a bare { name } declares nothing about
  // egress and now correctly produces no findings at all, so it can no longer
  // serve as the fixture for a compliance-reference assertion.
  const findings = networkBoundsRule.check(
    {
      name: "srv",
      network: { egressFilterEnabled: false, exposedHosts: ["127.0.0.1", "10.0.0.5"] },
    } as unknown as MCPServerConfig,
    ruleCtx
  );
  assert.ok(findings.length > 0);
  for (const finding of findings) {
    assert.deepEqual(finding.complianceRefs, ["palar:SSRF"]);
  }
});

// ---------------------------------------------------------------------------
// Accepted findings in the report.
//
// The rule under test is that acceptance is LOUD and CHANGES NOTHING about
// the assessment. A reader must be able to see what was accepted, why, and
// that the grade did not move on account of it.
// ---------------------------------------------------------------------------

function acceptedResult(over: Partial<Finding> = {}): AuditResult {
  const finding: Finding = {
    ruleId: "IV-101",
    pillar: "schema-integrity",
    severity: "critical",
    confidence: "confirmed",
    title: 'CONFIRMED command injection via "start_process.command"',
    detail: "a callback came back",
    location: {
      file: "mcp.tools.json",
      jsonPath: 'tools["start_process"].inputSchema.properties.command',
    },
    accepted: {
      reason: "desktop-commander is a shell tool; execution is the product",
      added: "2026-08-01",
      expires: "2027-01-01",
      acceptsConfirmed: true,
      daysUntilExpiry: 133,
    },
    ...over,
  };
  return {
    timestamp: "2026-08-21T00:00:00.000Z",
    toolsScanned: 1,
    serversScanned: 1,
    findings: [finding],
    score: computeScore([finding]),
    warnings: [],
  };
}

test("an accepted finding renders an ACCEPTED section with its reason", () => {
  const md = renderMarkdownReport(acceptedResult());
  assert.match(md, /## ACCEPTED — known, and shipped anyway/);
  assert.match(md, /desktop-commander is a shell tool/);
  assert.match(md, /2026-08-01/);
  assert.match(md, /2027-01-01/);
});

test("an accepted CONFIRMED finding says the grade is still F", () => {
  const result = acceptedResult();
  assert.equal(result.score.grade, "F", "precondition: confirmedForcesF still applies");
  const md = renderMarkdownReport(result);
  assert.match(md, /grade is still F/);
  assert.match(md, /CONFIRMED finding that the project has accepted/);
});

test("an accepted finding still appears in the pillar section at full severity", () => {
  // It must not vanish into the ACCEPTED table. The value is an auditor
  // seeing "known, accepted, because X" — not the finding disappearing.
  const md = renderMarkdownReport(acceptedResult());
  assert.match(md, /\[CRITICAL · CONFIRMED · ACCEPTED\] IV-101/);
  assert.match(md, /\| critical \| 1 \|/);
});

test("acceptance does not change the score or the grade", () => {
  const accepted = acceptedResult();
  const notAccepted = acceptedResult({ accepted: undefined });
  assert.deepEqual(accepted.score, notAccepted.score);
});

test("a report with no acceptances has no ACCEPTED section", () => {
  const md = renderMarkdownReport(acceptedResult({ accepted: undefined }));
  assert.doesNotMatch(md, /## ACCEPTED/);
});
