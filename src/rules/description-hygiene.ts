/**
 * DH: lexical hygiene of tool descriptions — descriptions long enough to eat
 * a real share of the model's context budget, phrases heuristically
 * associated with prompt injection, and missing or placeholder descriptions
 * that leave a reviewer nothing to review. Distinct from text-sanitizer,
 * which detects individual suspicious code points.
 *
 * Only DH-002 makes a claim about prompt injection. DH-001 is a size
 * observation and says so; see CONTEXT_BUDGET_REFS below for why it no
 * longer cites OWASP Tool Poisoning.
 */
import type { Finding, MCPToolDefinition } from "../core/types.js";
import type { RuleContext, ToolRule } from "./index.js";
import { DEFAULT_CONFIG } from "../core/config.js";

const COMPLIANCE_REFS = ["OWASP MCP03:2025 - Tool Poisoning"];

/**
 * DH-001 deliberately does NOT carry the Tool Poisoning citation the other
 * DH rules do. Length is not evidence of poisoning: a long description is
 * overwhelmingly just a complex tool documented thoroughly, and the actual
 * poisoning signal — instruction-like phrasing, hidden code points — is what
 * DH-002 and the TS-* rules detect directly. Citing MCP03 for "this text is
 * long" claims an alignment the evidence does not support, the same reason
 * network-bounds.ts uses "palar:SSRF" instead of an OWASP ID. What is left
 * once poisoning is removed is a real but much smaller concern: a single
 * description can eat a disproportionate share of the model's context
 * budget, so this is filed as its own internal category.
 */
const CONTEXT_BUDGET_REFS = ["palar:context-budget"];

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
        // A character count of text palar read. The detail already calls
        // it "a context-budget observation".
        confidence: "observed",
        severity: "low",
        title: `Very long description on tool "${tool.name}"`,
        detail:
          `Tool "${tool.name}" has a ${description.length}-character ` +
          `description (limit: ${settings.maxLength}), roughly ` +
          `${Math.round(description.length / 4)} tokens of context spent before ` +
          `the tool is even called. That is a context-budget observation, not ` +
          `evidence of anything hidden in the text: length alone does not ` +
          `indicate injected instructions, and DH-002 and the TS-* rules test ` +
          `for those directly. Complex tools legitimately need long descriptions.`,
        location: { file: ctx.file, jsonPath },
        remediation:
          `Only if context budget matters to you: trim the description to what ` +
          `a caller needs in order to choose and use the tool, and move ` +
          `reference material to documentation.`,
        complianceRefs: [...CONTEXT_BUDGET_REFS],
      });
    }

    if (description !== undefined) {
      const lower = description.toLowerCase();
      const matched = settings.injectionKeywords.filter((k) => lower.includes(k));
      if (matched.length > 0) {
        findings.push({
          ruleId: "DH-002",
          pillar: "text-sanitization",
          // The phrase is in the description, and a description is fed to
          // the model verbatim — so the exposure is realised at the point
          // palar read it, not conditional on unseen code.
          confidence: "observed",
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
        // The description is missing or placeholder. Nothing to infer.
        confidence: "observed",
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
