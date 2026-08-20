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

/** An MCP tool definition as declared in a local JSON file. */
export interface MCPToolDefinition {
  name: string;
  description?: string;
  inputSchema?: {
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

/** A single issue reported by a rule. */
export interface Finding {
  ruleId: string;
  pillar: Pillar;
  severity: Severity;
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
