/**
 * IV: flags string inputs on potentially sensitive fields that carry no
 * structural constraint, since a free-form string on a field like
 * `command` or `url` is an injection surface the schema could have
 * narrowed.
 *
 * ## Why IV-001 is medium and not high
 *
 * IV-001 decides "execution-adjacent" from the field's NAME. That is a
 * cheap and useful heuristic, and it is also the ceiling on what this rule
 * can know: nothing in a name tells you whether the value reaches
 * `exec()`, `fs.readFile()`, or a validator that rejects it. The two are
 * indistinguishable statically, and the ecosystem contains both in
 * quantity.
 *
 * Measured against six real servers, 24 of 29 findings were IV-001 on
 * fields that turned out not to be injectable. `server-filesystem` is the
 * clearest case: every one of its eleven `path` fields fired, and a live
 * probe showed palar's own payloads arriving as literal filenames
 * ("Parent directory does not exist: /tmp/<payload>") — there was no shell
 * to inject into, and containment was enforced in the handler rather than
 * in the schema, where this rule cannot see it. The inverse error exists
 * too: `browser_run_code_unsafe` describes itself as RCE-equivalent and
 * gets no finding, because `code` is not a keyword.
 *
 * HIGH asserts a confidence this method does not have, and palar's whole
 * position is "confirmed, not suspected". So the static tier states a
 * hypothesis at medium, in wording that says so, and the evidence tier
 * settles it: a CONFIRMED oracle callback on the same field escalates the
 * finding to critical (see live/escalate.ts). A `rejected` probe changes
 * nothing — one boolean covers four different meanings, one of which is a
 * successful injection.
 *
 * What this deliberately does NOT do is tune the keyword list. Better
 * keywords would move findings between these buckets without changing the
 * fact that a name cannot establish behavior.
 */
import type { Finding, JSONSchemaProperty, MCPToolDefinition } from "../core/types.js";
import type { RuleContext, ToolRule } from "./index.js";
import { DEFAULT_CONFIG, DEFAULT_LIMITS } from "../core/config.js";

const COMPLIANCE_REFS = ["OWASP MCP05:2025 - Command Injection & Execution"];

/**
 * Split an identifier into lowercase word segments ("filePath" → ["file",
 * "path"], "target_url" → ["target", "url"]) so keyword matching catches
 * compound names without firing on incidental substrings.
 *
 * Exported so the live-scan probe classifier (src/live/probes.ts) can reuse
 * the same execution-adjacent-field detection instead of re-implementing it.
 */
export function nameSegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^a-zA-Z0-9]+/)
    .filter((s) => s.length > 0)
    .map((s) => s.toLowerCase());
}

export function matchesSensitiveKeyword(name: string, keywords: Set<string>): boolean {
  return nameSegments(name).some((seg) => keywords.has(seg));
}

/**
 * Patterns that are present but match essentially anything, providing no
 * real constraint. List-based: anchors are stripped, then the body is
 * compared against known catch-all shapes.
 */
const TRIVIAL_PATTERN_BODIES = new Set([
  "",
  ".*",
  ".+",
  ".?",
  ".*?",
  ".+?",
  "(.*)",
  "(.+)",
  "(?:.*)",
  "(?:.+)",
  "[\\s\\S]*",
  "[\\s\\S]+",
  "[\\w\\W]*",
  "[\\w\\W]+",
  "[\\d\\D]*",
  "[\\d\\D]+",
  ".{0,}",
  ".{1,}",
]);

export function isTrivialPattern(pattern: string): boolean {
  let body = pattern.trim();
  if (body.startsWith("^")) body = body.slice(1);
  if (body.endsWith("$")) body = body.slice(0, -1);
  return TRIVIAL_PATTERN_BODIES.has(body);
}

/** True when the property declares a `pattern` that constrains nothing. */
export function hasVacuousPattern(prop: JSONSchemaProperty): boolean {
  return typeof prop.pattern === "string" && isTrivialPattern(prop.pattern);
}

/**
 * Does this schema keyword set actually narrow the *range of values* the
 * field accepts?
 *
 * The distinction is between keywords that restrict and keywords that
 * merely describe, and getting it wrong is not symmetric: a describing
 * keyword counted as a restriction silently suppresses both the static
 * finding AND the live probe, so the field is never examined by either
 * half of the tool.
 *
 * **Restricts** — an attacker's value set is genuinely smaller:
 *   - `enum`: the complete permitted set, written out.
 *   - `const`: exactly one permitted value.
 *   - `pattern`, when it is not one of the catch-all bodies above. A real
 *     regex excludes real strings.
 *
 * **Describes only** — deliberately NOT treated as constraints:
 *   - `format`: annotation, not assertion. JSON Schema makes format
 *     annotation-only unless a validator opts in, so the server may reject
 *     nothing at all. And even asserted, the values it excludes are the
 *     wrong ones: `format: "uri"` on a `url` field excludes strings that
 *     are not URIs, while every SSRF payload worth sending
 *     (`http://169.254.169.254/latest/meta-data/`, `file:///etc/passwd`)
 *     is a perfectly valid URI. Counting it cost palar the entire
 *     canonical server-side-fetch server in the ecosystem:
 *     mcp-server-fetch declares `{"type":"string","format":"uri"}` on its
 *     one URL field, and so produced no finding, no probe, and a 100/A.
 *   - `title`, `description`: documentation.
 *   - `minLength`/`maxLength`: bound the length, not the content. No
 *     length cap that admits a URL excludes `; curl http://attacker/`.
 *   - `default`: a value, not a restriction on values.
 *
 * Keyword *names* are a separate question from keyword *semantics*, and
 * this function is only about the latter — which fields count as
 * execution-adjacent is decided by the sensitive-keyword list, untouched
 * here on purpose so the two effects stay measurable apart.
 */
export function isConstrained(prop: JSONSchemaProperty): boolean {
  if (prop.enum !== undefined) return true;
  if (prop.const !== undefined) return true;
  return typeof prop.pattern === "string" && !isTrivialPattern(prop.pattern);
}

/**
 * Heuristic ReDoS detection — catches the classic catastrophic shapes:
 * - a quantified group whose entire body is one quantified atom,
 *   e.g. (a+)+, (.*)*, ([a-z]+)+, (\d+){2,}
 * - adjacent identical unbounded broad atoms, e.g. .*.* or \w+\w+
 * - a quantified alternation with duplicate branches, e.g. (a|a)+
 * It does NOT attempt full backtracking analysis: prefixed group bodies
 * like (-[a-z]+)* and polynomial multi-atom overlaps are not flagged.
 */
const REDOS_HEURISTICS: RegExp[] = [
  /\((?:\?:)?(?:\.|\[[^\]]*\]|\\[wWsSdD]|[A-Za-z0-9])[*+]\)(?:[*+]|\{\d+,)/,
  /(\.|\\[wWsSdD])[*+]\1[*+]/,
  /\(([^()|]+)\|\1\)(?:[*+]|\{\d+,)/,
];

function isRedosProne(pattern: string): boolean {
  return REDOS_HEURISTICS.some((h) => h.test(pattern));
}

interface WalkState {
  nodesVisited: number;
  maxDepth: number;
  maxNodes: number;
  depthHit: boolean;
  nodesHit: boolean;
}

function walkProperties(
  properties: Record<string, JSONSchemaProperty>,
  parentPath: string,
  visit: (name: string, path: string, prop: JSONSchemaProperty) => void,
  depth: number,
  state: WalkState
): void {
  for (const [name, prop] of Object.entries(properties)) {
    const path = parentPath === "" ? name : `${parentPath}.${name}`;
    walkProp(name, path, prop, visit, depth, state);
  }
}

function walkProp(
  name: string,
  path: string,
  prop: JSONSchemaProperty,
  visit: (name: string, path: string, prop: JSONSchemaProperty) => void,
  depth: number,
  state: WalkState
): void {
  // Raw JSON may put null or a scalar where a schema object belongs.
  if (typeof prop !== "object" || prop === null) return;
  if (depth > state.maxDepth) {
    state.depthHit = true;
    return;
  }
  if (state.nodesVisited >= state.maxNodes) {
    state.nodesHit = true;
    return;
  }
  state.nodesVisited += 1;
  visit(name, path, prop);
  if (prop.properties) {
    walkProperties(prop.properties, path, visit, depth + 1, state);
  }
  if (prop.items) {
    // Array items share the array's name; keep the path traceable.
    walkProp(name, `${path}[]`, prop.items, visit, depth + 1, state);
  }
}

export const inputValidationRule: ToolRule = {
  id: "input-validation",
  check(tool: MCPToolDefinition, ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];

    const limits = ctx.config?.limits ?? DEFAULT_LIMITS;
    const keywords = new Set(
      ctx.config?.sensitiveKeywords ?? DEFAULT_CONFIG.sensitiveKeywords
    );
    const state: WalkState = {
      nodesVisited: 0,
      maxDepth: limits.maxNestingDepth,
      maxNodes: limits.maxSchemaNodes,
      depthHit: false,
      nodesHit: false,
    };

    const properties = tool.inputSchema?.properties;
    if (properties) {
      walkProperties(properties, "", (name, path, prop) => {
        // IV-001 and IV-003 are mutually exclusive by construction: a
        // vacuous `pattern` is not a constraint (isConstrained says so),
        // but it is a more specific observation than "no constraint at
        // all", so IV-003 owns that case and IV-001 steps aside.
        if (
          prop.type === "string" &&
          matchesSensitiveKeyword(name, keywords) &&
          !isConstrained(prop) &&
          !hasVacuousPattern(prop)
        ) {
          findings.push({
            ruleId: "IV-001",
            pillar: "schema-integrity",
            // The whole rule is a name heuristic. It cannot see whether
            // this value reaches an interpreter, and the detail below says
            // so — the confidence has to agree with the prose.
            confidence: "hypothesized",
            // medium, not high. See this rule's header for the full
            // argument: the severity has to match what the method can
            // actually establish, and a field-name keyword cannot
            // establish that a value reaches an interpreter.
            severity: "medium",
            title: `Unconstrained input on potentially sensitive field "${path}" (unverified)`,
            detail:
              `Tool "${tool.name}" declares string property "${path}", whose NAME ` +
              `suggests it may feed a command, path, query, or network target, and ` +
              `the schema does not narrow the values it accepts (no enum, const, or ` +
              `non-trivial pattern). This is a hypothesis from the field's name and ` +
              `shape, not an observation of its behavior: static analysis cannot see ` +
              `whether "${path}" reaches a shell, a file API that treats it as a ` +
              `literal name, or nothing at all. Treat it as a place worth looking, ` +
              `not as a demonstrated injection. Only a confirmed out-of-band callback ` +
              `from \`palar live\` raises this to critical.`,
            location: {
              file: ctx.file,
              jsonPath: `tools["${tool.name}"].inputSchema.properties.${path}`,
            },
            remediation:
              `First establish what "${path}" actually does — run \`palar live\` ` +
              `against this server, or read the handler. If the value reaches an ` +
              `interpreter, fix that; a schema constraint is a defence-in-depth ` +
              `measure there, not the fix. If containment is already enforced in ` +
              `code (e.g. a path validated against an allowed-directory list), a ` +
              `schema "enum"/"const"/"pattern" may be neither necessary nor ` +
              `possible without breaking the tool, and this finding is expected to ` +
              `stand unresolved. Note that "format" does not narrow the accepted ` +
              `values and will not clear this finding.`,
            complianceRefs: [...COMPLIANCE_REFS],
          });
        }

        if (prop.type === "string" && typeof prop.pattern === "string") {
          if (
            matchesSensitiveKeyword(name, keywords) &&
            prop.enum === undefined &&
            prop.const === undefined &&
            isTrivialPattern(prop.pattern)
          ) {
            findings.push({
              ruleId: "IV-003",
              pillar: "schema-integrity",
              // The vacuous pattern is observed, but this rule only fires
              // on a keyword-matched field, so "execution-adjacent" — the
              // part that makes it matter — is still the IV-001 guess.
              confidence: "hypothesized",
              severity: "medium",
              title: `Trivial pattern on execution-adjacent field "${path}"`,
              detail:
                `Tool "${tool.name}" constrains "${path}" with the pattern ` +
                `"${prop.pattern}", which matches essentially any string. The ` +
                `pattern satisfies a presence check but provides no real ` +
                `constraint on an execution-adjacent field.`,
              location: {
                file: ctx.file,
                jsonPath: `tools["${tool.name}"].inputSchema.properties.${path}`,
              },
              remediation:
                `Replace the catch-all pattern on "${path}" with an allowlist ` +
                `regex, an enum, or a format that actually narrows accepted values.`,
              complianceRefs: [...COMPLIANCE_REFS],
            });
          }
          if (isRedosProne(prop.pattern)) {
            findings.push({
              ruleId: "IV-004",
              pillar: "schema-integrity",
              // The backtracking construct is really in the pattern, but
              // the finding is a DoS claim conditioned on "if a downstream
              // validator evaluates it" — code palar never read.
              confidence: "hypothesized",
              severity: "medium",
              title: `Backtracking-prone pattern on field "${path}"`,
              detail:
                `Tool "${tool.name}" constrains "${path}" with the pattern ` +
                `"${prop.pattern}", which contains a construct prone to ` +
                `catastrophic backtracking (nested or duplicated quantifiers). ` +
                `If a downstream validator evaluates it against ` +
                `attacker-controlled input, a crafted value can cause a ` +
                `denial-of-service. This is a heuristic match, not a full ` +
                `backtracking analysis.`,
              location: {
                file: ctx.file,
                jsonPath: `tools["${tool.name}"].inputSchema.properties.${path}`,
              },
              remediation:
                `Rewrite the pattern on "${path}" to avoid nested quantifiers ` +
                `(e.g. flatten "(a+)+" to "a+") so its worst-case matching ` +
                `time stays linear.`,
              complianceRefs: [...COMPLIANCE_REFS],
            });
          }
        }
      }, 0, state);
    } else if (matchesSensitiveKeyword(tool.name, keywords)) {
      findings.push({
        ruleId: "IV-002",
        pillar: "schema-integrity",
        // "Executes commands" inferred from the tool's NAME. Same ceiling
        // as IV-001.
        confidence: "hypothesized",
        severity: "low",
        title: `Execution-adjacent tool "${tool.name}" declares no input schema`,
        detail:
          `Tool "${tool.name}" has a name that suggests it executes commands, ` +
          `touches files, or reaches network targets, but declares no inputSchema. ` +
          `Without a schema there is no structural validation of what callers may ` +
          `pass to it.`,
        location: {
          file: ctx.file,
          jsonPath: `tools["${tool.name}"]`,
        },
        remediation:
          `Declare an inputSchema for "${tool.name}" with typed, constrained ` +
          `properties so inputs are validated structurally.`,
        complianceRefs: [...COMPLIANCE_REFS],
      });
    }

    if (state.depthHit) {
      ctx.warn?.(
        `${ctx.file}: tool "${tool.name}": schema nesting depth limit ` +
          `(${limits.maxNestingDepth}) reached; deeper schema branches were ` +
          `not analyzed by input-validation`
      );
    }
    if (state.nodesHit) {
      ctx.warn?.(
        `${ctx.file}: tool "${tool.name}": schema node limit ` +
          `(${limits.maxSchemaNodes}) reached; remaining schema was not ` +
          `analyzed by input-validation`
      );
    }

    return findings;
  },
};
