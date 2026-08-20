/**
 * CR: scans every string value in a discovered tool or server definition for
 * patterns that look like a hardcoded credential — AWS access keys, generic
 * api-key/token/secret literals, OpenAI-style keys, Slack tokens, bearer
 * tokens, and PEM private-key headers. A matched secret is never reproduced
 * in a finding: only a redacted first4...last2 form is shown, so the report
 * itself cannot leak a real credential if a live config is ever scanned.
 */
import type {
  Finding,
  MCPServerConfig,
  MCPToolDefinition,
  Severity,
} from "../core/types.js";
import type { RuleContext, ServerRule, ToolRule } from "./index.js";
import { DEFAULT_LIMITS } from "../core/config.js";

const COMPLIANCE_REFS = [
  "OWASP MCP01:2025 - Token Mismanagement & Secret Exposure",
];

interface CredentialPattern {
  ruleId: string;
  label: string;
  severity: Severity;
  regex: RegExp;
  /** Pull the actual secret substring out of a match, for redaction. */
  extractSecret: (match: RegExpExecArray) => string;
  /** False for structural markers (e.g. a PEM header) that are safe to show as-is. */
  sensitive: boolean;
}

const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  {
    ruleId: "CR-001",
    label: "AWS access key",
    severity: "critical",
    regex: /AKIA[0-9A-Z]{16}/g,
    extractSecret: (m) => m[0],
    sensitive: true,
  },
  {
    ruleId: "CR-002",
    label: "API key/token/secret literal",
    severity: "high",
    regex: /(?:api[_-]?key|token|secret)\s*[:=]\s*["']([A-Za-z0-9_-]{16,})["']/gi,
    extractSecret: (m) => m[1] ?? m[0],
    sensitive: true,
  },
  {
    ruleId: "CR-003",
    label: "OpenAI-style API key",
    severity: "high",
    regex: /sk-[A-Za-z0-9]{20,}/g,
    extractSecret: (m) => m[0],
    sensitive: true,
  },
  {
    ruleId: "CR-004",
    label: "Slack token",
    severity: "high",
    regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    extractSecret: (m) => m[0],
    sensitive: true,
  },
  {
    ruleId: "CR-005",
    label: "Bearer token",
    severity: "high",
    regex: /Bearer\s+([A-Za-z0-9._-]{20,})/gi,
    extractSecret: (m) => m[1] ?? m[0],
    sensitive: true,
  },
  {
    ruleId: "CR-006",
    label: "PEM private key block header",
    severity: "critical",
    regex: /-----BEGIN (?:RSA |EC |)PRIVATE KEY-----/g,
    extractSecret: (m) => m[0],
    sensitive: false,
  },
];

/** Show only the first 4 and last 2 characters, e.g. "sk-F...34". */
function redact(secret: string): string {
  if (secret.length <= 6) return "*".repeat(secret.length);
  return `${secret.slice(0, 4)}...${secret.slice(-2)}`;
}

interface PatternHit {
  count: number;
  shown: string[];
}

/** Tally credential-pattern matches in a single string, grouped by pattern. */
function scanText(text: string): Map<CredentialPattern, PatternHit> {
  const hits = new Map<CredentialPattern, PatternHit>();
  for (const pattern of CREDENTIAL_PATTERNS) {
    // Global regexes carry state across calls (lastIndex); reset before use.
    pattern.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    const shown: string[] = [];
    while ((match = pattern.regex.exec(text)) !== null) {
      const secret = pattern.extractSecret(match);
      shown.push(pattern.sensitive ? redact(secret) : secret);
      if (match[0].length === 0) pattern.regex.lastIndex += 1;
    }
    if (shown.length > 0) {
      hits.set(pattern, { count: shown.length, shown });
    }
  }
  return hits;
}

interface WalkState {
  nodesVisited: number;
  maxDepth: number;
  maxNodes: number;
  depthHit: boolean;
  nodesHit: boolean;
}

/**
 * Walk every string leaf in an arbitrary parsed-JSON value — config fields,
 * env defaults, schema examples/defaults, anywhere a string literal can
 * appear — not just the fields other rules already know about.
 */
function walkStrings(
  value: unknown,
  path: string,
  depth: number,
  state: WalkState,
  visit: (path: string, text: string) => void
): void {
  if (depth > state.maxDepth) {
    state.depthHit = true;
    return;
  }
  if (state.nodesVisited >= state.maxNodes) {
    state.nodesHit = true;
    return;
  }
  state.nodesVisited += 1;

  if (typeof value === "string") {
    visit(path, value);
  } else if (Array.isArray(value)) {
    value.forEach((item, index) =>
      walkStrings(item, `${path}[${index}]`, depth + 1, state, visit)
    );
  } else if (typeof value === "object" && value !== null) {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      walkStrings(child, `${path}.${key}`, depth + 1, state, visit);
    }
  }
}

function buildFindings(
  root: unknown,
  rootPath: string,
  ctx: RuleContext,
  subjectLabel: string
): Finding[] {
  const findings: Finding[] = [];
  const limits = ctx.config?.limits ?? DEFAULT_LIMITS;
  const state: WalkState = {
    nodesVisited: 0,
    maxDepth: limits.maxNestingDepth,
    maxNodes: limits.maxSchemaNodes,
    depthHit: false,
    nodesHit: false,
  };

  walkStrings(root, rootPath, 0, state, (path, text) => {
    for (const [pattern, hit] of scanText(text)) {
      findings.push({
        ruleId: pattern.ruleId,
        pillar: "credential-exposure",
        severity: pattern.severity,
        // The literal is in the file palar read. Whether the credential is
        // still valid is not knowable from here and is not what the finding
        // claims — the exposure is the presence, and the presence is read.
        confidence: "observed",
        title: `Possible ${pattern.label} in ${subjectLabel}`,
        detail:
          `Found ${hit.count} occurrence(s) matching a ${pattern.label} pattern ` +
          `at "${path}": ${hit.shown.join(", ")}. Hardcoded credentials in a ` +
          `tool or server definition file are exposed to anyone who can read ` +
          `the file, including its version control history.`,
        location: { file: ctx.file, jsonPath: path },
        remediation:
          `Move this value to an environment variable or a secret manager, ` +
          `reference it indirectly at runtime, and never commit the literal ` +
          `credential to the schema/config file — rotate it if it has already ` +
          `been committed.`,
        complianceRefs: [...COMPLIANCE_REFS],
      });
    }
  });

  if (state.depthHit) {
    ctx.warn?.(
      `${ctx.file}: ${subjectLabel}: nesting depth limit ` +
        `(${limits.maxNestingDepth}) reached; deeper values were not ` +
        `analyzed by credential-scanner`
    );
  }
  if (state.nodesHit) {
    ctx.warn?.(
      `${ctx.file}: ${subjectLabel}: node limit ` +
        `(${limits.maxSchemaNodes}) reached; remaining values were not ` +
        `analyzed by credential-scanner`
    );
  }

  return findings;
}

export const credentialScannerToolRule: ToolRule = {
  id: "credential-scanner-tool",
  check(tool: MCPToolDefinition, ctx: RuleContext): Finding[] {
    return buildFindings(tool, `tools["${tool.name}"]`, ctx, `tool "${tool.name}"`);
  },
};

export const credentialScannerServerRule: ServerRule = {
  id: "credential-scanner-server",
  check(server: MCPServerConfig, ctx: RuleContext): Finding[] {
    return buildFindings(
      server,
      `servers["${server.name}"]`,
      ctx,
      `server "${server.name}"`
    );
  },
};
