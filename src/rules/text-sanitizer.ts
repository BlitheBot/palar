/**
 * TS: detects suspicious Unicode code points in tool names and descriptions —
 * invisible characters, bidi overrides, tag characters, and stray controls
 * that can hide or reorder text a human reviewer would otherwise see. The
 * rule only reports presence, counts, and code points; it never interprets
 * or reproduces the hidden content.
 */
import type { Finding, MCPToolDefinition, Severity } from "../core/types.js";
import type { RuleContext, ToolRule } from "./index.js";
import type { UnicodeCategoryName } from "../core/config.js";
import { DEFAULT_CONFIG, parseCodePointRanges } from "../core/config.js";

const COMPLIANCE_REFS = ["MCP-TOP10:B2-ToolPoisoning"];

interface CodePointCategory {
  ruleId: string;
  label: string;
  severity: Severity;
  matches(cp: number): boolean;
}

/** Fixed category identity; the code-point ranges come from config. */
const CATEGORY_META: {
  key: UnicodeCategoryName;
  ruleId: string;
  label: string;
  severity: Severity;
}[] = [
  {
    key: "zeroWidth",
    ruleId: "TS-001",
    label: "zero-width/invisible characters",
    severity: "high",
  },
  {
    key: "bidi",
    ruleId: "TS-002",
    label: "bidirectional override controls",
    severity: "critical",
  },
  {
    key: "tagChars",
    ruleId: "TS-003",
    label: "Unicode tag characters",
    severity: "critical",
  },
  {
    key: "variationSelectors",
    ruleId: "TS-004",
    label: "variation selectors",
    severity: "low",
  },
  {
    key: "controlChars",
    ruleId: "TS-005",
    label: "non-printable control characters",
    severity: "medium",
  },
];

function buildCategories(
  categoryRanges: Record<UnicodeCategoryName, string[]>
): CodePointCategory[] {
  return CATEGORY_META.map(({ key, ruleId, label, severity }) => {
    const ranges = parseCodePointRanges(categoryRanges[key]);
    return {
      ruleId,
      label,
      severity,
      matches: (cp: number) => ranges.some(([lo, hi]) => cp >= lo && cp <= hi),
    };
  });
}

function formatCodePoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

interface CategoryHits {
  count: number;
  codePoints: Set<number>;
}

/** Tally suspicious code points in a field, grouped by category. */
function scanField(
  text: string,
  categories: CodePointCategory[]
): Map<CodePointCategory, CategoryHits> {
  const hits = new Map<CodePointCategory, CategoryHits>();
  for (const char of text) {
    const cp = char.codePointAt(0);
    if (cp === undefined) continue;
    for (const category of categories) {
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
    const categories = buildCategories(
      ctx.config?.unicodeCategories ?? DEFAULT_CONFIG.unicodeCategories
    );

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
      for (const [category, { count, codePoints }] of scanField(text, categories)) {
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
