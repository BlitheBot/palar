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
 *
 * Sharing isConstrained() with IV-001 also means the two share its
 * failure modes, which is exactly why that function no longer counts
 * `format` as a constraint: a describing keyword treated as a restricting
 * one suppressed the static finding AND the probe together, so the field
 * went unexamined by both halves of the tool rather than one. See
 * isConstrained()'s docstring for the restricts/describes split.
 */
import {
  matchesSensitiveKeyword,
  isConstrained,
  isTrivialPattern,
} from "../rules/input-validation.js";
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
// neither subset (custom keywords added via .palarrc.json) fall back to
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
          ? `field name "${name}" matches a network-target keyword and the schema does not narrow ` +
            `its accepted values (no enum, const, or non-trivial pattern)`
          : `field name "${name}" matches an execution-adjacent keyword and the schema does not narrow ` +
            `its accepted values (no enum, const, or non-trivial pattern)`,
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
 * POSIX shell payload: appends a callback request after the legitimate
 * value with ";" (sh command separator) so the callback fires regardless
 * of what the original command does with the base value.
 *
 * Always POSIX, deliberately not keyed on process.platform. The payload
 * never runs on PALAR's host: a stdio target executes it inside the Linux
 * node:20-slim sandbox container (see sandbox.ts / docker/target-runtime),
 * and an SSE target executes it on a remote host whose OS PALAR cannot
 * observe. PALAR's own platform is therefore never the shell that runs
 * this string — branching on it emitted cmd.exe syntax (curl.exe, "&"
 * which backgrounds instead of chaining, ">NUL") into a shell that has
 * never been cmd.exe, which is exactly why the oracle could not confirm
 * command injection from a Windows host.
 */
export function buildCommandInjectionPayload(baseValue: string, callbackUrl: string): string {
  return `${baseValue}; curl -s -m 3 "${callbackUrl}" >/dev/null 2>&1 || true`;
}

/** SSRF payload is just the callback URL itself as the "legitimate" value. */
export function buildSsrfPayload(callbackUrl: string): string {
  return callbackUrl;
}

/**
 * ## Filler values, and why a wrong one is not a cosmetic problem
 *
 * A probe puts its payload on ONE field. Every other value in the same
 * call is filler palar invents, and filler that the target's own schema
 * rejects bounces the whole call at argument validation — before the
 * handler runs, before the payload is ever interpreted. The probe then
 * comes back looking like the target pushed back on the payload, when in
 * fact palar broke its own request.
 *
 * That is not hypothetical. desktop-commander puts
 * `origin: {"type":"string","enum":["ui","llm"]}` on eight tools, this
 * function ignored `enum`, and so every one of those probes died on a zod
 * enum error carrying the literal string "palar-live-probe". Among them
 * was `start_process.command`, which really does reach a shell — the one
 * genuine true positive in that server, reported as though the target had
 * refused it.
 *
 * So filler generation has one job: produce a value the DECLARED schema
 * accepts. Where it cannot (a `pattern` there is no general way to
 * satisfy), it says so, structurally, rather than letting the resulting
 * bounce be misread as evidence about the target — see
 * `ProbeArgumentIssue` and status.ts's `not-tested`.
 *
 * ### The `format` asymmetry with isConstrained()
 *
 * isConstrained() deliberately does NOT count `format` as a constraint,
 * and this code deliberately DOES honor it. That reads like a
 * contradiction and is not: the two ask different questions. isConstrained
 * asks "does this narrow the values an ATTACKER can send?" — `format:
 * "uri"` does not, since every SSRF payload worth sending is a valid URI.
 * This asks "will a validator that happens to assert it reject OUR benign
 * filler?" — and "palar-live-probe" is not a URI, so a server using zod's
 * `.url()` rejects it. Honoring format here costs nothing (this code never
 * fills the payload's own field) and removes a bounce class; counting it
 * there cost palar an entire server class.
 */

/** Max recursion depth when building nested filler objects/arrays. */
const MAX_FILLER_DEPTH = 8;

const BASE_STRING = "palar-live-probe";

/**
 * Canned values for the `format` values a validator is actually likely to
 * assert (zod's `.url()`, `.email()`, `.uuid()`, `.datetime()` and friends
 * all surface as one of these through zod-to-json-schema).
 *
 * An UNKNOWN format is deliberately not treated as a problem: JSON Schema
 * requires validators to ignore formats they do not implement, so an
 * unrecognized one is not a bounce risk worth reporting.
 */
const FORMAT_VALUES: Record<string, string> = {
  uri: "https://example.invalid/palar-live-probe",
  url: "https://example.invalid/palar-live-probe",
  "uri-reference": "/palar-live-probe",
  iri: "https://example.invalid/palar-live-probe",
  email: "palar-live-probe@example.invalid",
  "idn-email": "palar-live-probe@example.invalid",
  hostname: "palar-live-probe.example.invalid",
  "idn-hostname": "palar-live-probe.example.invalid",
  ipv4: "127.0.0.1",
  ipv6: "::1",
  uuid: "00000000-0000-4000-8000-000000000000",
  "date-time": "2000-01-01T00:00:00.000Z",
  date: "2000-01-01",
  time: "00:00:00",
  duration: "PT1S",
  "relative-json-pointer": "0",
  regex: "palar-live-probe",
  byte: "cGFsYXItbGl2ZS1wcm9iZQ==",
};

/**
 * One declared constraint palar could not produce a satisfying value for.
 *
 * This is the structural half of the `not-tested` signal: it is known
 * BEFORE the call is sent, from the target's own advertised schema, with
 * no inspection of any error text. See status.ts for what is and is not
 * knowable about the other half.
 */
export interface ProbeArgumentIssue {
  /** Dotted path of the offending property within the call arguments. */
  fieldPath: string;
  /** True when this is the field the payload itself went on. */
  isTarget: boolean;
  /** Statement of the declared constraint and why palar's value does not meet it. */
  detail: string;
}

interface PlannedValue {
  value: unknown;
  issues: ProbeArgumentIssue[];
}

function issue(fieldPath: string, detail: string): ProbeArgumentIssue {
  return { fieldPath, isTarget: false, detail };
}

function firstBranch(prop: JSONSchemaProperty): JSONSchemaProperty | null {
  for (const key of ["anyOf", "oneOf"] as const) {
    const branches = prop[key];
    if (Array.isArray(branches) && branches.length > 0) {
      const first = branches[0];
      if (typeof first === "object" && first !== null) return first as JSONSchemaProperty;
    }
  }
  return null;
}

/** The declared type, tolerating `type: ["string","null"]` and inferring from shape. */
function resolveType(prop: JSONSchemaProperty): string {
  // Read through `unknown`: JSONSchemaProperty declares `type?: string`,
  // but JSON Schema also permits an array of type names and real servers
  // emit it (`["string","null"]` for a nullable field). Narrowing off the
  // declared type alone would make that branch unreachable.
  const declared = prop.type as unknown;
  if (typeof declared === "string") return declared;
  if (Array.isArray(declared)) {
    // Prefer a non-null branch: `["string","null"]` means "a string, or
    // absent-ish", and a string is the more useful filler of the two.
    const named = declared.find((t) => typeof t === "string" && t !== "null");
    if (typeof named === "string") return named;
    if (declared.length > 0) return "null";
  }
  if (prop.properties !== undefined) return "object";
  if (prop.items !== undefined) return "array";
  return "string";
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function planString(prop: JSONSchemaProperty, path: string): PlannedValue {
  const issues: ProbeArgumentIssue[] = [];
  const format = typeof prop.format === "string" ? prop.format : undefined;
  const formatted = format !== undefined && format in FORMAT_VALUES;
  let value = formatted ? FORMAT_VALUES[format!]! : BASE_STRING;

  // A non-trivial `pattern` is the one string constraint with no general
  // solution — inverting an arbitrary regex is not something to attempt
  // here. The filler is sent anyway (plenty of servers never enforce the
  // pattern they declare), but the call is marked so that a bounce is not
  // read as the target refusing the payload.
  if (typeof prop.pattern === "string" && !isTrivialPattern(prop.pattern)) {
    issues.push(
      issue(
        path,
        `declares pattern "${prop.pattern}", and palar cannot synthesize a string matching an ` +
          `arbitrary regex, so its filler value ${JSON.stringify(value)} probably does not match`
      )
    );
  }

  const minLength = asNumber(prop.minLength);
  const maxLength = asNumber(prop.maxLength);
  if (minLength !== undefined && maxLength !== undefined && minLength > maxLength) {
    issues.push(
      issue(path, `declares minLength ${minLength} above maxLength ${maxLength}, which nothing satisfies`)
    );
    return { value, issues };
  }
  if (minLength !== undefined && value.length < minLength) {
    if (formatted) {
      // Padding a URI/UUID/date to reach minLength would break the format
      // it was chosen to satisfy. Report rather than break one to fix the
      // other.
      issues.push(
        issue(
          path,
          `declares format "${format}" and minLength ${minLength}; the format-satisfying filler ` +
            `${JSON.stringify(value)} is shorter than that, and padding it would break the format`
        )
      );
    } else {
      value = value.padEnd(minLength, "x");
    }
  }
  if (maxLength !== undefined && value.length > maxLength) {
    if (formatted) {
      issues.push(
        issue(
          path,
          `declares format "${format}" and maxLength ${maxLength}; truncating the ` +
            `format-satisfying filler to fit would break the format`
        )
      );
    } else {
      value = value.slice(0, maxLength);
    }
  }

  return { value, issues };
}

function planNumber(prop: JSONSchemaProperty, path: string, integer: boolean): PlannedValue {
  const issues: ProbeArgumentIssue[] = [];
  // Bounds are normalized to an inclusive [lo, hi]. draft-04's boolean
  // form of exclusiveMinimum/Maximum is ignored on purpose: the numeric
  // form is what schema generators emit, and reading `true` as 1 would
  // invent a bound nobody declared.
  const step = integer ? 1 : Number.EPSILON * 8;
  let lo = asNumber(prop.minimum);
  let hi = asNumber(prop.maximum);
  const exLo = asNumber(prop.exclusiveMinimum);
  const exHi = asNumber(prop.exclusiveMaximum);
  if (exLo !== undefined) lo = Math.max(lo ?? -Infinity, exLo + step);
  if (exHi !== undefined) hi = Math.min(hi ?? Infinity, exHi - step);

  let value = 1;
  if (lo !== undefined && value < lo) value = lo;
  if (hi !== undefined && value > hi) value = hi;
  if (integer) value = Math.ceil(value);

  const multipleOf = asNumber(prop.multipleOf);
  if (multipleOf !== undefined && multipleOf > 0) {
    const rounded = Math.ceil(value / multipleOf) * multipleOf;
    if (hi !== undefined && rounded > hi) {
      issues.push(
        issue(path, `declares multipleOf ${multipleOf} with maximum ${hi}, leaving no multiple in range`)
      );
    } else {
      value = rounded;
    }
  }

  if ((lo !== undefined && value < lo) || (hi !== undefined && value > hi)) {
    issues.push(
      issue(
        path,
        `declares bounds palar cannot satisfy with ${integer ? "an integer" : "a number"} ` +
          `(minimum ${lo ?? "none"}, maximum ${hi ?? "none"})`
      )
    );
  }
  return { value, issues };
}

function planArray(prop: JSONSchemaProperty, path: string, depth: number): PlannedValue {
  const issues: ProbeArgumentIssue[] = [];
  const minItems = asNumber(prop.minItems) ?? 0;
  const maxItems = asNumber(prop.maxItems);
  if (maxItems !== undefined && minItems > maxItems) {
    issues.push(
      issue(path, `declares minItems ${minItems} above maxItems ${maxItems}, which nothing satisfies`)
    );
    return { value: [], issues };
  }
  // An empty array satisfies every array schema that does not demand
  // members, and is the least behavior-perturbing thing to send.
  if (minItems <= 0) return { value: [], issues };

  const items = prop.items;
  const value: unknown[] = [];
  for (let i = 0; i < minItems; i += 1) {
    // Tuple-form `items` runs out before minItems does when
    // additionalItems is open; reusing the last entry is the closest
    // approximation available without modelling additionalItems.
    const itemSchema = Array.isArray(items)
      ? (items[Math.min(i, items.length - 1)] as JSONSchemaProperty | undefined)
      : items;
    const planned = planValue(itemSchema, `${path}[${i}]`, depth + 1);
    value.push(planned.value);
    issues.push(...planned.issues);
  }
  return { value, issues };
}

function planObject(prop: JSONSchemaProperty, path: string, depth: number): PlannedValue {
  const issues: ProbeArgumentIssue[] = [];
  const value: Record<string, unknown> = {};
  const properties = prop.properties ?? {};
  const required = Array.isArray(prop.required) ? prop.required : [];

  // Required sub-properties only, for the same reason the top level sends
  // required properties only — see buildProbeArguments.
  for (const name of required) {
    if (typeof name !== "string") continue;
    const planned = planValue(properties[name], path === "" ? name : `${path}.${name}`, depth + 1);
    value[name] = planned.value;
    issues.push(...planned.issues);
  }

  const minProperties = asNumber(prop.minProperties);
  if (minProperties !== undefined && Object.keys(value).length < minProperties) {
    // Fill from declared optionals before giving up; only an object that
    // demands more members than it declares is genuinely unsatisfiable.
    for (const [name, sub] of Object.entries(properties)) {
      if (Object.keys(value).length >= minProperties) break;
      if (name in value) continue;
      const planned = planValue(sub, path === "" ? name : `${path}.${name}`, depth + 1);
      value[name] = planned.value;
      issues.push(...planned.issues);
    }
    if (Object.keys(value).length < minProperties) {
      issues.push(
        issue(path, `declares minProperties ${minProperties} but names too few properties to reach it`)
      );
    }
  }

  return { value, issues };
}

/**
 * Builds one filler value from a declared property schema, together with
 * whatever that schema demands and palar could not deliver.
 *
 * Recursive, and bounded: a self-referential or pathologically deep schema
 * stops at MAX_FILLER_DEPTH and is reported rather than followed.
 */
function planValue(
  prop: JSONSchemaProperty | undefined,
  path: string,
  depth = 0
): PlannedValue {
  if (typeof prop !== "object" || prop === null) return { value: BASE_STRING, issues: [] };
  if (depth > MAX_FILLER_DEPTH) {
    return {
      value: null,
      issues: [issue(path, `nests deeper than palar's filler depth limit (${MAX_FILLER_DEPTH})`)],
    };
  }

  // enum/const pin the value outright and outrank every other keyword —
  // including `type`, which they are allowed to disagree with. This is the
  // desktop-commander `origin` case, and it comes first for that reason.
  if (Array.isArray(prop.enum)) {
    if (prop.enum.length === 0) {
      return { value: null, issues: [issue(path, `declares an empty "enum", which nothing satisfies`)] };
    }
    return { value: prop.enum[0], issues: [] };
  }
  if (prop.const !== undefined) return { value: prop.const, issues: [] };

  // allOf is an intersection, and palar does not merge subschemas. One
  // entry is just a wrapper and is safe to descend into; several is a
  // conjunction whose solution palar cannot compute, so it says so.
  const allOf = prop.allOf;
  if (Array.isArray(allOf) && allOf.length > 0 && prop.type === undefined) {
    if (allOf.length === 1 && typeof allOf[0] === "object" && allOf[0] !== null) {
      return planValue(allOf[0] as JSONSchemaProperty, path, depth + 1);
    }
    return {
      value: BASE_STRING,
      issues: [
        issue(path, `declares "allOf" over ${allOf.length} subschemas, which palar does not merge`),
      ],
    };
  }

  if (prop.type === undefined) {
    const branch = firstBranch(prop);
    if (branch) return planValue(branch, path, depth + 1);
  }

  switch (resolveType(prop)) {
    case "number":
      return planNumber(prop, path, false);
    case "integer":
      return planNumber(prop, path, true);
    case "boolean":
      return { value: true, issues: [] };
    case "null":
      return { value: null, issues: [] };
    case "array":
      return planArray(prop, path, depth);
    case "object":
      return planObject(prop, path, depth);
    default:
      return planString(prop, path);
  }
}

/**
 * A harmless filler value for a field the probe isn't targeting, honoring
 * whatever the declared schema demands of it. See the block comment above
 * for why an unsatisfying filler is a correctness problem and not a
 * cosmetic one; use buildProbeArguments() when you also need to know what
 * the schema demanded and did not get.
 */
export function benignValueFor(prop: JSONSchemaProperty | undefined): unknown {
  return planValue(prop, "").value;
}

export interface ProbeArgumentPlan {
  args: Record<string, unknown>;
  /**
   * Declared constraints this argument set provably does not satisfy. Non-
   * empty means a failed call has a sufficient explanation in palar's own
   * input, so it says nothing about the target field — see status.ts.
   */
  issues: ProbeArgumentIssue[];
}

/**
 * The payload's own field gets the payload, not filler — but the schema
 * can still declare something the payload does not satisfy (a maxLength
 * shorter than the injection string, a format an asserting validator
 * checks). That bounces the call for palar's own reasons just as squarely
 * as bad filler does, so it is reported the same way.
 *
 * `pattern`, `enum` and `const` are absent by construction: a field
 * carrying any of them is constrained, and classifyExecutionAdjacentFields
 * never selects a constrained field as a target.
 */
function targetFieldIssues(
  prop: JSONSchemaProperty | undefined,
  fieldPath: string,
  payload: string
): ProbeArgumentIssue[] {
  if (typeof prop !== "object" || prop === null) return [];
  const issues: ProbeArgumentIssue[] = [];
  const minLength = asNumber(prop.minLength);
  const maxLength = asNumber(prop.maxLength);
  if (minLength !== undefined && payload.length < minLength) {
    issues.push({
      fieldPath,
      isTarget: true,
      detail: `declares minLength ${minLength}, and this probe's ${payload.length}-character payload is shorter`,
    });
  }
  if (maxLength !== undefined && payload.length > maxLength) {
    issues.push({
      fieldPath,
      isTarget: true,
      detail: `declares maxLength ${maxLength}, and this probe's ${payload.length}-character payload is longer`,
    });
  }
  const format = typeof prop.format === "string" ? prop.format : undefined;
  if (format !== undefined && format in FORMAT_VALUES && format !== "regex") {
    // Only flagged for a payload that is not itself of that shape. An SSRF
    // payload IS a URI, which is exactly the point isConstrained() makes
    // about format not narrowing anything.
    const uriish = format === "uri" || format === "url" || format === "iri";
    const looksLikeUri = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(payload);
    if (!(uriish && looksLikeUri)) {
      issues.push({
        fieldPath,
        isTarget: true,
        detail:
          `declares format "${format}"; if the target asserts that rather than treating it as ` +
          `an annotation, this probe's payload does not satisfy it`,
      });
    }
  }
  return issues;
}

/**
 * Full call arguments: the payload on the probed field, schema-satisfying
 * filler on every OTHER REQUIRED property, and nothing else.
 *
 * ## Why optional properties are omitted rather than filled
 *
 * Filling them was the previous behavior and it is wrong twice over.
 *
 * The cheap reason is that every extra field is another chance to bounce
 * on a constraint. The expensive one is that an optional field is a knob,
 * and inventing a value for a knob changes what the tool does:
 * desktop-commander's `start_process` declares an optional
 * `shell: {"type":"string"}`, so filling it asked the target to run the
 * payload through a shell named "palar-live-probe", which does not exist.
 * That value is perfectly schema-valid — no validator would have caught
 * it — and it would have stopped the injection from ever running while
 * looking like a clean result.
 *
 * The minimum the schema demands, plus the payload, is the only argument
 * set whose behavior the schema actually describes. Omitting optionals
 * also lets the target apply its own declared defaults, which is what a
 * real caller would get.
 */
export function buildProbeArguments(
  tool: LiveTool,
  target: FieldProbeTarget,
  payload: string
): ProbeArgumentPlan {
  const args: Record<string, unknown> = {};
  const issues: ProbeArgumentIssue[] = [];
  const properties = tool.inputSchema.properties ?? {};
  const required = new Set(
    Array.isArray(tool.inputSchema.required)
      ? tool.inputSchema.required.filter((n): n is string => typeof n === "string")
      : []
  );

  for (const name of Object.keys(properties)) {
    if (name === target.fieldPath) continue;
    if (!required.has(name)) continue;
    const planned = planValue(properties[name], name);
    args[name] = planned.value;
    issues.push(...planned.issues);
  }

  args[target.fieldPath] = payload;
  issues.push(...targetFieldIssues(properties[target.fieldPath], target.fieldPath, payload));

  return { args, issues };
}
