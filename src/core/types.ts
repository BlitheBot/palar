/**
 * Shared types for mcpguard — a read-only static analyzer for local MCP
 * tool and server definition files.
 */

/** A JSON-schema-like property within a tool's input schema. */
export interface JSONSchemaProperty {
  type?: string;
  description?: string;
  enum?: unknown[];
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
  network?: MCPServerNetworkConfig;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** High-level category a rule belongs to. */
export type Pillar =
  | "schema-integrity"
  | "text-sanitization"
  | "network-boundaries";

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

/** A baseline of tool definition hashes, used to detect drift over time. */
export interface SchemaSnapshot {
  /** ISO-8601 timestamp of when the snapshot was taken. */
  createdAt: string;
  /** Tool name → SHA-256 hash of its canonicalized definition. */
  tools: Record<string, string>;
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
