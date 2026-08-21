/**
 * Reading a tool's self-declared annotations, in exactly one place.
 *
 * ## Why this is a module and not three inline property reads
 *
 * Two independent paths reach a tool definition: `scan` reads it from a
 * JSON file on disk, `live`/`--from-*` reads it from a running server's
 * `listTools()`. They already share the rule set so that both judge the
 * same schema the same way. Annotations have to share a reader for the
 * same reason and one more: the title lives in TWO spec positions and the
 * hints have non-obvious defaults, so "just read `tool.annotations`" is a
 * decision with a wrong answer, and making it twice means eventually
 * making it differently. A server whose title `scan` finds and `live`
 * misses would produce two reports that disagree about the same bytes.
 *
 * ## The two title positions
 *
 * The 2025-06-18 spec revision added a top-level `title` to Tool; before
 * that, a display name went in `annotations.title`. Both are in active
 * use — of the six targets in palar's sample, two carry `annotations.title`
 * and three carry the top-level one — so reading either position alone
 * misses real titles. Precedence follows the spec: top-level `title`
 * wins, then `annotations.title`. `name` is deliberately NOT a fallback
 * here: this module answers "did the server declare a display title?",
 * and substituting the identifier would make an undeclared title
 * indistinguishable from a declared one that happens to equal the name.
 *
 * ## Why absence never degrades to the default
 *
 * The spec's hint defaults are all on the dangerous side — `readOnlyHint`
 * false, `destructiveHint` true, `idempotentHint` false, `openWorldHint`
 * true. It is tempting to resolve an absent hint to its default and report
 * a value either way, and that is exactly the mistake this module refuses
 * to make: a report line saying `readOnlyHint: false` reads as something
 * the server SAID, when in fact the server said nothing. Findings and
 * report fields derived from a hint therefore degrade to "not declared",
 * and only a hint the server actually wrote is ever reported as a value.
 *
 * Note the asymmetry that follows, and that it is correct: the DRIFT axis
 * does care about the defaults, because a tool that starts declaring
 * `readOnlyHint: true` where it previously declared nothing has moved from
 * the spec's dangerous default to a safety claim. That reasoning lives in
 * snapshot.ts, on a comparison between two declarations — not here, where
 * a single declaration is being read.
 */
import type { MCPToolAnnotations, MCPToolDefinition } from "./types.js";

/** The four boolean hints, in spec order. Title is handled separately. */
export const ANNOTATION_HINTS = [
  "readOnlyHint",
  "destructiveHint",
  "idempotentHint",
  "openWorldHint",
] as const;

export type AnnotationHint = (typeof ANNOTATION_HINTS)[number];

/** A minimal structural view of anything carrying MCP tool annotations. */
export interface AnnotatedTool {
  name?: string;
  title?: string;
  annotations?: MCPToolAnnotations;
}

/**
 * Where a declared title was found, or that it was not declared at all.
 * The position is carried, not just the text, so a finding on a title can
 * point at the field the server actually used.
 */
export type ResolvedTitle =
  | { declared: true; text: string; position: "title" | "annotations.title" }
  | { declared: false };

export function resolveToolTitle(tool: AnnotatedTool): ResolvedTitle {
  if (typeof tool.title === "string") {
    return { declared: true, text: tool.title, position: "title" };
  }
  const nested = tool.annotations?.title;
  if (typeof nested === "string") {
    return { declared: true, text: nested, position: "annotations.title" };
  }
  return { declared: false };
}

/**
 * One boolean hint as the server declared it, or `undefined` when it did
 * not. Non-boolean values in the field are treated as undeclared rather
 * than coerced: a hint written as the string "true" is not a boolean the
 * spec describes, and guessing what was meant would invent a declaration.
 */
export function readHint(
  tool: AnnotatedTool,
  hint: AnnotationHint
): boolean | undefined {
  const value = tool.annotations?.[hint];
  return typeof value === "boolean" ? value : undefined;
}

/** Every hint the server actually declared, keyed by name. Absent keys were not declared. */
export function declaredHints(tool: AnnotatedTool): Partial<Record<AnnotationHint, boolean>> {
  const declared: Partial<Record<AnnotationHint, boolean>> = {};
  for (const hint of ANNOTATION_HINTS) {
    const value = readHint(tool, hint);
    if (value !== undefined) declared[hint] = value;
  }
  return declared;
}

/**
 * How a hint is written into a report. The single reason this exists is
 * the third case: an undeclared hint renders as "not declared" and never
 * as its spec default, so no reader is ever shown a value the server did
 * not write. See the module docstring.
 */
export function describeHint(value: boolean | undefined): string {
  return value === undefined ? "not declared" : String(value);
}

/** Convenience for reports: `readOnlyHint: not declared`. */
export function describeToolHint(tool: AnnotatedTool, hint: AnnotationHint): string {
  return `${hint}: ${describeHint(readHint(tool, hint))}`;
}

/**
 * A tool definition's title as a display surface for the TS-* rules —
 * text plus the JSON path of the position it came from.
 */
export function titleField(
  tool: MCPToolDefinition
): { text: string; position: "title" | "annotations.title" } | null {
  const resolved = resolveToolTitle(tool);
  return resolved.declared ? { text: resolved.text, position: resolved.position } : null;
}
