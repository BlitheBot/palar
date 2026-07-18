/**
 * TS: detects suspicious Unicode code points in tool names and descriptions —
 * invisible characters, bidi overrides, tag characters, and stray controls
 * that can hide or reorder text a human reviewer would otherwise see. The
 * rule only reports presence, counts, and code points; it never interprets
 * or reproduces the hidden content.
 */
import type { Finding, MCPToolDefinition, Severity } from "../core/types.js";
import type { RuleContext, ToolRule } from "./index.js";

const COMPLIANCE_REFS = ["MCP-TOP10:B2-ToolPoisoning"];

interface CodePointCategory {
  ruleId: string;
  label: string;
  severity: Severity;
  matches(cp: number): boolean;
}

const ZERO_WIDTH = new Set([0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);
const ALLOWED_CONTROLS = new Set([0x09, 0x0a, 0x0d]); // \t \n \r

const CATEGORIES: CodePointCategory[] = [
  {
    ruleId: "TS-001",
    label: "zero-width/invisible characters",
    severity: "high",
    matches: (cp) => ZERO_WIDTH.has(cp),
  },
  {
    ruleId: "TS-002",
    label: "bidirectional override controls",
    severity: "critical",
    matches: (cp) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069),
  },
  {
    ruleId: "TS-003",
    label: "Unicode tag characters",
    severity: "critical",
    matches: (cp) => cp >= 0xe0000 && cp <= 0xe007f,
  },
  {
    ruleId: "TS-004",
    label: "variation selectors",
    severity: "low",
    matches: (cp) => cp >= 0xfe00 && cp <= 0xfe0f,
  },
  {
    ruleId: "TS-005",
    label: "non-printable control characters",
    severity: "medium",
    matches: (cp) =>
      !ALLOWED_CONTROLS.has(cp) &&
      (cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)),
  },
];

function formatCodePoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

interface CategoryHits {
  count: number;
  codePoints: Set<number>;
}

/** Tally suspicious code points in a field, grouped by category. */
function scanField(text: string): Map<CodePointCategory, CategoryHits> {
  const hits = new Map<CodePointCategory, CategoryHits>();
  for (const char of text) {
    const cp = char.codePointAt(0);
    if (cp === undefined) continue;
    for (const category of CATEGORIES) {
      if (category.matches(cp)) {
        let entry = hits.get(category);
        if (!entry) {
          entry = { count: 0, codePoints: new Set() };
          hits.set(category, entry);
        }
        entry.count += 1;
        entry.codePoints.add(cp);
        break;
      }
    }
  }
  return hits;
}

export const textSanitizerRule: ToolRule = {
  id: "text-sanitizer",
  check(tool: MCPToolDefinition, ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    const fields: { fieldName: string; jsonPath: string; text: string }[] = [];
    // Raw JSON may put non-strings in these fields; only scan real strings.
    if (typeof tool.name === "string") {
      fields.push({
        fieldName: "name",
        jsonPath: `tools["${tool.name}"].name`,
        text: tool.name,
      });
    }
    if (typeof tool.description === "string") {
      fields.push({
        fieldName: "description",
        jsonPath: `tools["${tool.name}"].description`,
        text: tool.description,
      });
    }

    for (const { fieldName, jsonPath, text } of fields) {
      for (const [category, { count, codePoints }] of scanField(text)) {
        const points = [...codePoints]
          .sort((a, b) => a - b)
          .map(formatCodePoint)
          .join(", ");
        findings.push({
          ruleId: category.ruleId,
          pillar: "text-sanitization",
          severity: category.severity,
          title: `Suspicious ${category.label} in tool ${fieldName}`,
          detail:
            `The "${fieldName}" field of tool "${tool.name}" contains ${count} ` +
            `occurrence(s) of ${category.label} (${points}). These code points ` +
            `can conceal or reorder text so that what a human reviewer sees ` +
            `differs from what a model or parser receives.`,
          location: { file: ctx.file, jsonPath },
          remediation:
            `Strip or reject these code points from the "${fieldName}" field, and ` +
            `review the field's visible text against its raw bytes before trusting it.`,
          complianceRefs: [...COMPLIANCE_REFS],
        });
      }
    }

    return findings;
  },
};
