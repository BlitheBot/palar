/**
 * Shared types for palar — a read-only static analyzer for local MCP
 * tool and server definition files.
 */

/** A JSON-schema-like property within a tool's input schema. */
export interface JSONSchemaProperty {
  type?: string;
  description?: string;
  enum?: unknown[];
  /** JSON Schema draft-6+ single permitted value. Narrows a field to exactly one string. */
  const?: unknown;
  default?: unknown;
  items?: JSONSchemaProperty;
  properties?: Record<string, JSONSchemaProperty>;
  required?: string[];
  [key: string]: unknown;
}

/**
 * The MCP `ToolAnnotations` object: a tool's own claims about what calling
 * it does.
 *
 * Every field is a HINT, and the spec says so in as many words — a client
 * is told not to trust these from an untrusted server. palar therefore
 * treats them as text the target wrote about itself, never as a property
 * palar established. That distinction is load-bearing in two places: the
 * drift axis (see snapshot.ts's `claim-relaxed`) and the contradiction
 * class (see live/annotation-contradiction.ts), both of which exist
 * precisely because a claim and a constraint are different kinds of fact.
 *
 * The spec's defaults are the dangerous side of each hint —
 * `readOnlyHint: false`, `destructiveHint: true`, `idempotentHint: false`,
 * `openWorldHint: true` — so an ABSENT hint is not a neutral state, and
 * palar must not silently substitute the default for a declaration that
 * was never made. See core/annotations.ts's describeHint().
 */
export interface MCPToolAnnotations {
  /** Display name for the tool, the `annotations.title` position. See resolveToolTitle(). */
  title?: string;
  /** Claims the tool does not modify its environment. Spec default: false. */
  readOnlyHint?: boolean;
  /** Claims the tool may perform destructive updates. Spec default: true. */
  destructiveHint?: boolean;
  /** Claims repeated calls with the same arguments have no additional effect. Spec default: false. */
  idempotentHint?: boolean;
  /** Claims the tool may interact with an open world of external entities. Spec default: true. */
  openWorldHint?: boolean;
  [key: string]: unknown;
}

/** An MCP tool definition as declared in a local JSON file. */
export interface MCPToolDefinition {
  name: string;
  /**
   * The top-level `title` position, added in the 2025-06-18 spec revision.
   * A tool may carry a title HERE or under `annotations.title` — both are
   * live in the wild, and palar reads both. Never read this field
   * directly; go through resolveToolTitle(), which knows the precedence.
   */
  title?: string;
  description?: string;
  annotations?: MCPToolAnnotations;
  inputSchema?: {
    type?: string;
    properties?: Record<string, JSONSchemaProperty>;
    required?: string[];
    [key: string]: unknown;
  };
  /**
   * Declared shape of the tool's RESULT. Carried through so it is not
   * silently dropped between the live and static paths; no rule reads it
   * yet, and one that does must say what it establishes.
   */
  outputSchema?: {
    type?: string;
    properties?: Record<string, JSONSchemaProperty>;
    required?: string[];
    [key: string]: unknown;
  };
}

/** Network posture declared for an MCP server. */
export interface MCPServerNetworkConfig {
  egressAllowlist?: string[];
  egressFilterEnabled?: boolean;
  exposedHosts?: string[];
}

/** An MCP server configuration as declared in a local JSON file. */
export interface MCPServerConfig {
  name: string;
  transport?: "stdio" | "sse" | "streamable-http" | string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  /** Endpoint URL for non-stdio transports ("sse", "streamable-http"). */
  url?: string;
  network?: MCPServerNetworkConfig;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** High-level category a rule belongs to. */
export type Pillar =
  | "schema-integrity"
  | "text-sanitization"
  | "network-boundaries"
  | "credential-exposure";

/** Where in a scanned file a finding was observed. */
export interface FindingLocation {
  file: string;
  /** JSON path within the file, e.g. "tools[2].description". */
  jsonPath?: string;
  line?: number;
}

/**
 * How much of a finding palar actually saw, as opposed to inferred.
 *
 * Orthogonal to severity, and the two answer different questions. Severity
 * asks *how bad is this if it is real*; confidence asks *how much of this
 * did palar establish rather than guess*. Collapsing them is what made
 * server-filesystem score 20/F on eleven findings whose own text calls them
 * hypotheses, while desktop-commander's callback-proven shell injection
 * carried the same weight per finding as a field name that merely looked
 * dangerous.
 *
 * The test that assigns this is one question: **does the finding assert
 * something palar did not read?**
 *
 *   - `confirmed`    — palar ran it and watched it happen. Today that means
 *     exactly one thing: an out-of-band callback bearing this probe's nonce
 *     arrived at palar's own listener. Nothing else in the codebase may
 *     claim this value, because nothing else has evidence of that kind.
 *   - `observed`     — the defect is fully present in the artifact palar
 *     read. A bidi override IS in the description; an AWS key IS in the
 *     file; `exposedHosts[0]` IS a loopback address. There is no further
 *     fact to establish — the finding is complete as read.
 *   - `hypothesized` — the finding's severity depends on runtime behaviour
 *     palar never saw. Every static input-validation rule lands here: they
 *     infer "this value reaches an interpreter" from the field's NAME, and
 *     IV-001's own detail text says so in as many words.
 *
 * Deliberately a REQUIRED field rather than an optional one with a default.
 * A default is a decision made by whoever forgets to think about it, and
 * both directions are wrong in a way that matters: defaulting to `observed`
 * scores a new hypothesis-shaped rule ~2.4x too harshly, and defaulting to
 * `hypothesized` scores a new evidence-shaped rule ~4x too softly. Making
 * it required turns "a new rule must state what kind of claim it is" into a
 * compile error rather than a code-review habit.
 */
export type Confidence = "confirmed" | "observed" | "hypothesized";

/** A single issue reported by a rule. */
export interface Finding {
  ruleId: string;
  pillar: Pillar;
  severity: Severity;
  /** What palar established vs. inferred. See Confidence — required on purpose. */
  confidence: Confidence;
  title: string;
  detail: string;
  location: FindingLocation;
  remediation?: string;
  complianceRefs?: string[];
}

export type LetterGrade = "A" | "B" | "C" | "D" | "F";

export interface AuditScore {
  /** 0–100, higher is better. */
  value: number;
  grade: LetterGrade;
}

/** Per-property structural summary stored in a snapshot for semantic diffing. */
export interface PropertySummary {
  type?: string | string[];
  /** Whether the property is listed in its parent's "required" array. */
  required?: boolean;
  /**
   * Scalar constraints (pattern, format, minLength, maxLength, minimum,
   * maximum, minItems, maxItems) plus enumCount — enum values themselves
   * are not stored, only their count, to bound snapshot size.
   */
  constraints: Record<string, string | number>;
}

/** One tool's entry in a v2 snapshot. */
export interface ToolSnapshotEntry {
  /** SHA-256 of the canonicalized definition (the change detector). */
  hash: string;
  /** Length of the description (0 when absent); text is not stored. */
  descriptionLength: number;
  /**
   * The tool's resolved display title, absent when it declared none.
   *
   * Stored as TEXT, unlike the description, because a title is a short
   * label rather than a body of prose — there is nothing to bound here,
   * and a diff that can say what the label changed FROM and TO is worth
   * far more on a display surface than a character count would be.
   *
   * Resolved across both spec positions (see core/annotations.ts), so a
   * server migrating a title from `annotations.title` to the top-level
   * field does not read as a title change. It is not the same string as
   * the tool's `name` when no title was declared: absent means absent.
   */
  title?: string;
  /**
   * The boolean annotation hints the tool DECLARED, keyed by hint name.
   *
   * An absent key means the server did not declare that hint — it is
   * never filled in with the spec's default, because the default and the
   * declaration are different facts and the drift comparison needs to
   * tell them apart. Moving from "not declared" to a safety claim is
   * itself the interesting transition (see snapshot.ts's SAFER_CLAIM).
   */
  annotations?: Record<string, boolean>;
  /** Flattened property path ("config.command", "args[]") → summary. */
  properties: Record<string, PropertySummary>;
}

/** A baseline of tool definitions, used to detect drift over time. */
export interface SchemaSnapshot {
  /** 2 for structured snapshots; absent on legacy hash-only (v1) files. */
  snapshotVersion?: number;
  /** ISO-8601 timestamp of when the snapshot was taken. */
  createdAt: string;
  /** Tool name → entry (v2) or bare hash string (legacy v1). */
  tools: Record<string, ToolSnapshotEntry | string>;
}

/** The result of a full audit run. */
export interface AuditResult {
  /** ISO-8601 timestamp of when the audit ran. */
  timestamp: string;
  toolsScanned: number;
  serversScanned: number;
  findings: Finding[];
  score: AuditScore;
  /** Discovery-time warnings (malformed or skipped files). */
  warnings: string[];
}

/**
 * What `palar scan --json` writes to stdout.
 *
 * A discriminated union, because a scan has more outcomes than "here are
 * the findings" and they must not be encoded as a findings list that
 * happens to be empty. Every case where palar examined nothing carries
 * **no `score` field at all** — the alternative is what `scan --json`
 * used to do on an empty directory: emit 100/100 grade A, which is a
 * statement about definitions that were never read. An absent score cannot
 * be misread; a perfect one for zero inputs is read exactly wrong, and it
 * is read that way by the CI job that treats it as a passing gate.
 *
 * `examined` carries the full AuditResult inline, so existing consumers
 * that reach straight for `.score` or `.findings` keep working — the
 * `outcome` field is additive on that case and load-bearing on the others.
 */
export type ScanJsonDocument =
  | ({ outcome: "examined" } & AuditResult)
  /** Nothing on disk matched the discovery patterns under the given roots. */
  | {
      outcome: "nothing-discovered";
      timestamp: string;
      searched: string[];
      warnings: string[];
    }
  /** A live source answered the handshake and reported zero tools. */
  | { outcome: "no-tools"; timestamp: string; source: string }
  /** A live source was never reached at all, so nothing is known about it. */
  | { outcome: "never-reached"; timestamp: string; source: string; error: string };
