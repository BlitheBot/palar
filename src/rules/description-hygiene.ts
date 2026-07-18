/**
 * DH: lexical hygiene of tool descriptions — oversized descriptions that
 * can stuff a model's context, phrases heuristically associated with
 * prompt injection, and missing or placeholder descriptions that leave a
 * reviewer nothing to review. Distinct from text-sanitizer, which detects
 * individual suspicious code points.
 */
import type { Finding, MCPToolDefinition } from "../core/types.js";
import type { RuleContext, ToolRule } from "./index.js";
import { DEFAULT_CONFIG } from "../core/config.js";

const COMPLIANCE_REFS = ["MCP-TOP10:B2-ToolPoisoning"];

/** Single generic words that describe nothing. */
const GENERIC_PLACEHOLDERS = new Set([
  "tool",
  "run",
  "test",
  "todo",
  "tbd",
  "n/a",
  "none",
  "description",
  "placeholder",
]);

/** Lowercase and strip non-alphanumerics, so "Deploy Service" ~ "deploy_service". */
function normalizeForComparison(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export const descriptionHygieneRule: ToolRule = {
  id: "description-hygiene",
  check(tool: MCPToolDefinition, ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const settings = ctx.config?.description ?? DEFAULT_CONFIG.description;
    const jsonPath = `tools["${tool.name}"].description`;
    const description =
      typeof tool.description === "string" ? tool.description : undefined;
    const trimmed = description?.trim() ?? "";

    if (description !== undefined && description.length > settings.maxLength) {
      findings.push({
        ruleId: "DH-001",
        pillar: "text-sanitization",
        severity: "medium",
        title: `Oversized description on tool "${tool.name}"`,
        detail:
          `Tool "${tool.name}" has a ${description.length}-character ` +
          `description (limit: ${settings.maxLength}). Very long descriptions ` +
          `are a context-stuffing vector: they consume model context and give ` +
          `injected instructions room to hide.`,
        location: { file: ctx.file, jsonPath },
        remediation:
          `Trim the description to what a caller needs to choose and use the ` +
          `tool; move reference material to documentation.`,
        complianceRefs: [...COMPLIANCE_REFS],
      });
    }

    if (description !== undefined) {
      const lower = description.toLowerCase();
      const matched = settings.injectionKeywords.filter((k) => lower.includes(k));
      if (matched.length > 0) {
        findings.push({
          ruleId: "DH-002",
          pillar: "text-sanitization",
          severity: "medium",
          title: `Possible injection phrasing in description of "${tool.name}"`,
          detail:
            `The description of tool "${tool.name}" contains phrase(s) commonly ` +
            `associated with prompt injection: ` +
            `${matched.map((m) => `"${m}"`).join(", ")}. This is a keyword ` +
            `heuristic — legitimate descriptions can trigger it — but these ` +
            `phrases have no business in a tool description and deserve review.`,
          location: { file: ctx.file, jsonPath },
          remediation:
            `Review the description's intent; remove instruction-like phrasing ` +
            `aimed at the model rather than at the human/tool caller.`,
          complianceRefs: [...COMPLIANCE_REFS],
        });
      }
    }

    const isPlaceholder =
      description === undefined ||
      trimmed.length === 0 ||
      GENERIC_PLACEHOLDERS.has(trimmed.toLowerCase()) ||
      normalizeForComparison(trimmed) === normalizeForComparison(tool.name);
    if (isPlaceholder) {
      const what =
        description === undefined
          ? "no description"
          : trimmed.length === 0
            ? "an empty description"
            : `the placeholder description "${trimmed}"`;
      findings.push({
        ruleId: "DH-003",
        pillar: "text-sanitization",
        severity: "low",
        title: `Missing or placeholder description on tool "${tool.name}"`,
        detail:
          `Tool "${tool.name}" has ${what}. Without a meaningful description, ` +
          `reviewers and callers cannot judge what the tool does or whether ` +
          `its behavior matches its declared intent.`,
        location: { file: ctx.file, jsonPath },
        remediation:
          `Write a one-or-two-sentence description of what the tool does, its ` +
          `inputs, and its effects.`,
        complianceRefs: [...COMPLIANCE_REFS],
      });
    }

    return findings;
  },
};
