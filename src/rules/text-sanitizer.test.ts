import { test } from "node:test";
import assert from "node:assert/strict";
import { textSanitizerRule } from "./text-sanitizer.js";
import type { MCPToolDefinition } from "../core/types.js";

const ctx = { file: "test.json" };
const check = (tool: unknown) =>
  textSanitizerRule.check(tool as MCPToolDefinition, ctx);

// Built from code points so this source file contains no literal
// invisible/control characters itself.
const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);
const BIDI_RLO = String.fromCodePoint(0x202e);
const TAG_CHAR = String.fromCodePoint(0xe0041);
const VARIATION_SELECTOR = String.fromCodePoint(0xfe0f);
const BEL_CONTROL = String.fromCodePoint(0x07);

const CATEGORY_CASES: [label: string, char: string, ruleId: string, severity: string][] = [
  ["zero-width space", ZERO_WIDTH_SPACE, "TS-001", "high"],
  ["bidi override", BIDI_RLO, "TS-002", "critical"],
  ["Unicode tag character", TAG_CHAR, "TS-003", "critical"],
  ["variation selector", VARIATION_SELECTOR, "TS-004", "low"],
  ["control character", BEL_CONTROL, "TS-005", "medium"],
];

for (const [label, char, ruleId, severity] of CATEGORY_CASES) {
  test(`${label} in description fires ${ruleId}`, () => {
    const findings = check({
      name: "clean_tool",
      description: `hello${char}world`,
    });
    assert.equal(findings.length, 1);
    assert.equal(findings[0]!.ruleId, ruleId);
    assert.equal(findings[0]!.severity, severity);
    assert.ok(findings[0]!.location.jsonPath?.endsWith(".description"));
  });
}

test("plain ASCII text produces no findings", () => {
  const findings = check({
    name: "clean_tool",
    description: "A perfectly ordinary description, with tabs\tand\nnewlines.",
  });
  assert.deepEqual(findings, []);
});

test("repeated occurrences collapse into one finding with a count", () => {
  const findings = check({
    name: "clean_tool",
    description: `a${ZERO_WIDTH_SPACE}b${ZERO_WIDTH_SPACE}c${ZERO_WIDTH_SPACE}`,
  });
  assert.equal(findings.length, 1);
  assert.ok(findings[0]!.detail.includes("3 occurrence(s)"));
  assert.ok(findings[0]!.detail.includes("U+200B"));
});

test("suspicious characters in the tool name are scanned too", () => {
  const findings = check({ name: `bad${ZERO_WIDTH_SPACE}name` });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, "TS-001");
  assert.ok(findings[0]!.location.jsonPath?.endsWith(".name"));
});

const CYRILLIC_A = String.fromCodePoint(0x0430);
const GREEK_OMICRON = String.fromCodePoint(0x03bf);
const FULLWIDTH_P = String.fromCodePoint(0xff50);

test("a Latin name with an embedded Cyrillic homoglyph fires TS-006", () => {
  const findings = check({ name: `p${CYRILLIC_A}y` });
  assert.deepEqual(findings.map((f) => f.ruleId), ["TS-006"]);
  assert.equal(findings[0]!.severity, "high");
  assert.ok(findings[0]!.detail.includes("U+0430"));
  assert.ok(findings[0]!.detail.includes("Cyrillic"));
});

test("a Greek look-alike inside a Latin word fires TS-006", () => {
  const findings = check({ name: `l${GREEK_OMICRON}g_tool` });
  assert.deepEqual(findings.map((f) => f.ruleId), ["TS-006"]);
  assert.ok(findings[0]!.detail.includes("U+03BF"));
});

test("a compatibility form (fullwidth letter) fires TS-006 via NFKC", () => {
  const findings = check({ name: `${FULLWIDTH_P}ay` });
  assert.deepEqual(findings.map((f) => f.ruleId), ["TS-006"]);
  assert.ok(findings[0]!.detail.includes("U+FF50"));
  assert.ok(findings[0]!.detail.includes("NFKC"));
});

test("plain ASCII names do not fire TS-006", () => {
  assert.deepEqual(check({ name: "payment_tool" }), []);
});

test("a consistently non-Latin name does not fire TS-006", () => {
  const cyrillicOnly = [0x043e, 0x043f, 0x043b, 0x0430, 0x0442, 0x0430]
    .map((cp) => String.fromCodePoint(cp))
    .join("");
  assert.deepEqual(check({ name: cyrillicOnly }), []);
});

test("non-string description does not throw", () => {
  assert.deepEqual(check({ name: "clean_tool", description: 123 }), []);
});

test("missing description does not throw", () => {
  assert.deepEqual(check({ name: "clean_tool" }), []);
});
