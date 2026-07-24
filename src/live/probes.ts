/**
 * Probe classification and payload construction for the live scan.
 *
 * Deliberately reuses the existing static-rule logic rather than
 * re-implementing "what looks like an execution-adjacent field" or "what
 * looks like a poisoned description" a second time:
 *   - matchesSensitiveKeyword / isConstrained from rules/input-validation.ts
 *     (the IV-001 detector)
 *   - the zeroWidth code-point ranges from core/config.ts (the TS-001
 *     detector in rules/text-sanitizer.ts)
 *
 * This means probing is generic — it targets whatever a live tool's schema
 * and description actually look like, not a hardcoded list of
 * fixture-specific tool/field names. Against fixtures/vuln-server this
 * naturally targets run_diagnostic.hostname, fetch_url.url, and
 * summarize_text.description without any special-casing of those names.
 */
import { matchesSensitiveKeyword, isConstrained } from "../rules/input-validation.js";
import { DEFAULT_CONFIG, parseCodePointRanges } from "../core/config.js";
import type { JSONSchemaProperty } from "../core/types.js";

/** Minimal shape of a tool as returned by the live Client.listTools() call. */
export interface LiveTool {
  name: string;
  description?: string;
  inputSchema: {
    type?: string;
    properties?: Record<string, JSONSchemaProperty>;
    required?: string[];
    [key: string]: unknown;
  };
}

export type ProbeKind = "command-injection" | "ssrf";

export interface FieldProbeTarget {
  toolName: string;
  fieldPath: string;
  kind: ProbeKind;
  reason: string;
}

// The same identifier segments IV-001 treats as execution-adjacent
// (core/config.ts DEFAULT_CONFIG.sensitiveKeywords), split into the two
// probe styles we know how to craft a real payload for. Fields matching
// neither subset (custom keywords added via .mcpguardrc.json) fall back to
// the command-injection style, since a shell-metacharacter payload is the
// cheaper of the two false-positive-wise: it either fires or is inert.
const SSRF_KEYWORDS = new Set(["url", "uri", "endpoint"]);

function classifyKind(fieldName: string): ProbeKind {
  const isNetwork = matchesSensitiveKeyword(fieldName, SSRF_KEYWORDS);
  return isNetwork ? "ssrf" : "command-injection";
}

/**
 * Top-level string properties only — matching the same shallowness as
 * where this pass's payload injection actually happens. Nested
 * execution-adjacent fields (e.g. under a "config" object) are flagged
 * statically by IV-001 already but are not probed live in this pass.
 */
export function classifyExecutionAdjacentFields(
  tool: LiveTool,
  sensitiveKeywords: string[] = DEFAULT_CONFIG.sensitiveKeywords
): FieldProbeTarget[] {
  const keywords = new Set(sensitiveKeywords);
  const properties = tool.inputSchema.properties;
  if (!properties) return [];

  const targets: FieldProbeTarget[] = [];
  for (const [name, prop] of Object.entries(properties)) {
    if (typeof prop !== "object" || prop === null) continue;
    if (prop.type !== "string") continue;
    if (!matchesSensitiveKeyword(name, keywords)) continue;
    if (isConstrained(prop)) continue;
    const kind = classifyKind(name);
    targets.push({
      toolName: tool.name,
      fieldPath: name,
      kind,
      reason:
        kind === "ssrf"
          ? `field name "${name}" matches a network-target keyword and has no pattern/enum/format constraint`
          : `field name "${name}" matches an execution-adjacent keyword and has no pattern/enum/format constraint`,
    });
  }
  return targets;
}

export interface PoisoningCheckTarget {
  toolName: string;
  codePoints: number[];
}

/** Reuses the exact zero-width ranges TS-001 checks, on the live description. */
export function detectPoisonedDescription(
  tool: LiveTool,
  zeroWidthRanges: string[] = DEFAULT_CONFIG.unicodeCategories.zeroWidth
): PoisoningCheckTarget | null {
  if (typeof tool.description !== "string") return null;
  const ranges = parseCodePointRanges(zeroWidthRanges);
  const found = new Set<number>();
  for (const char of tool.description) {
    const cp = char.codePointAt(0);
    if (cp === undefined) continue;
    if (ranges.some(([lo, hi]) => cp >= lo && cp <= hi)) found.add(cp);
  }
  return found.size > 0 ? { toolName: tool.name, codePoints: [...found].sort((a, b) => a - b) } : null;
}

/**
 * Platform-aware shell payload: appends a callback request after the
 * legitimate value using the metacharacter the host's default shell for
 * child_process.exec() honors ("&" for cmd.exe on Windows, ";" for
 * /bin/sh elsewhere) so the callback fires regardless of what the
 * original command does with the base value.
 */
export function buildCommandInjectionPayload(baseValue: string, callbackUrl: string): string {
  if (process.platform === "win32") {
    return `${baseValue} & curl.exe -s -m 3 "${callbackUrl}" >NUL 2>&1`;
  }
  return `${baseValue}; curl -s -m 3 "${callbackUrl}" >/dev/null 2>&1 || true`;
}

/** SSRF payload is just the callback URL itself as the "legitimate" value. */
export function buildSsrfPayload(callbackUrl: string): string {
  return callbackUrl;
}

/** A harmless filler value for a required field the probe isn't targeting. */
export function benignValueFor(prop: JSONSchemaProperty | undefined): unknown {
  const type = typeof prop?.type === "string" ? prop.type : "string";
  switch (type) {
    case "number":
    case "integer":
      return 1;
    case "boolean":
      return true;
    case "array":
      return [];
    case "object":
      return {};
    default:
      return "mcpguard-live-probe";
  }
}

/** Full call arguments: benign filler for every property, payload on the probed field. */
export function buildProbeArguments(
  tool: LiveTool,
  target: FieldProbeTarget,
  payload: string
): Record<string, unknown> {
  const args: Record<string, unknown> = {};
  const properties = tool.inputSchema.properties ?? {};
  for (const name of Object.keys(properties)) {
    args[name] = name === target.fieldPath ? payload : benignValueFor(properties[name]);
  }
  if (!(target.fieldPath in args)) {
    args[target.fieldPath] = payload;
  }
  return args;
}
