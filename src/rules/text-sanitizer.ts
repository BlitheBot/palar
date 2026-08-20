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

const COMPLIANCE_REFS = ["OWASP MCP03:2025 - Tool Poisoning"];

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

const LATIN_LETTER = /[A-Za-z]/;
/**
 * Scripts whose letters commonly pass as Latin look-alikes. Detection is
 * script-mixing based (Latin + one of these inside a single identifier
 * word) rather than an enumerated confusables table — broader coverage of
 * the same spoofing attack with nothing to maintain. A name written
 * consistently in one non-Latin script never fires.
 */
const CONFUSABLE_SCRIPTS: { script: string; matches: RegExp }[] = [
  { script: "Cyrillic", matches: /[Ѐ-ӿ]/u },
  { script: "Greek", matches: /[Ͱ-Ͽ]/u },
];

interface ConfusableHit {
  cp: number;
  reason: string;
}

/** Mixed-script look-alikes and NFKC compatibility forms in an identifier. */
function detectConfusables(name: string): ConfusableHit[] {
  const hits = new Map<number, ConfusableHit>();
  const words = name.split(/[^\p{L}\p{N}]+/u).filter((w) => w.length > 0);
  for (const word of words) {
    if (!LATIN_LETTER.test(word)) continue;
    for (const char of word) {
      const cp = char.codePointAt(0);
      if (cp === undefined) continue;
      for (const { script, matches } of CONFUSABLE_SCRIPTS) {
        if (matches.test(char)) {
          hits.set(cp, {
            cp,
            reason: `${script} letter inside an otherwise-Latin word`,
          });
        }
      }
    }
  }
  if (name.normalize("NFKC") !== name) {
    for (const char of name) {
      if (char.normalize("NFKC") !== char) {
        const cp = char.codePointAt(0);
        if (cp !== undefined && !hits.has(cp)) {
          hits.set(cp, {
            cp,
            reason: "compatibility form that changes under NFKC normalization",
          });
        }
      }
    }
  }
  return [...hits.values()].sort((a, b) => a.cp - b.cp);
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
          // The code points are in the text, counted and listed by
          // position. There is nothing further to establish: a bidi
          // override IS the defect, not a sign of one.
          confidence: "observed",
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

    if (typeof tool.name === "string") {
      const confusables = detectConfusables(tool.name);
      if (confusables.length > 0) {
        const listed = confusables
          .map((h) => `${formatCodePoint(h.cp)} (${h.reason})`)
          .join("; ");
        findings.push({
          ruleId: "TS-006",
          pillar: "text-sanitization",
          severity: "high",
          // The confusable character is present in the name palar read.
          confidence: "observed",
          title: `Confusable characters in tool name "${tool.name}"`,
          detail:
            `The name of tool "${tool.name}" contains character(s) that can ` +
            `visually impersonate a different identifier: ${listed}. Mixing ` +
            `Latin with look-alike letters from another script (or using ` +
            `compatibility forms) is how a malicious tool spoofs a ` +
            `legitimate-looking name. A name written consistently in a single ` +
            `script does not trigger this check.`,
          location: { file: ctx.file, jsonPath: `tools["${tool.name}"].name` },
          remediation:
            `Rename the tool using a single script (plain ASCII if the rest of ` +
            `the name is ASCII), and treat an unexplained look-alike character ` +
            `as a spoofing attempt.`,
          complianceRefs: [...COMPLIANCE_REFS],
        });
      }
    }

    return findings;
  },
};
