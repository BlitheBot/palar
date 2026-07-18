/**
 * IV: flags execution-adjacent string inputs that carry no structural
 * constraint, since a free-form string on a field like `command` or `url`
 * is an injection surface the schema could have narrowed.
 */
import type { Finding, JSONSchemaProperty, MCPToolDefinition } from "../core/types.js";
import type { RuleContext, ToolRule } from "./index.js";
import { DEFAULT_LIMITS } from "../core/config.js";

const SENSITIVE_KEYWORDS = new Set([
  "command",
  "cmd",
  "path",
  "file",
  "exec",
  "execute",
  "query",
  "sql",
  "shell",
  "script",
  "url",
  "uri",
  "endpoint",
  "host",
  "arg",
  "args",
]);

const COMPLIANCE_REFS = ["MCP-TOP10:A1-InjectionSurface"];

/**
 * Split an identifier into lowercase word segments ("filePath" → ["file",
 * "path"], "target_url" → ["target", "url"]) so keyword matching catches
 * compound names without firing on incidental substrings.
 */
function nameSegments(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^a-zA-Z0-9]+/)
    .filter((s) => s.length > 0)
    .map((s) => s.toLowerCase());
}

function matchesSensitiveKeyword(name: string): boolean {
  return nameSegments(name).some((seg) => SENSITIVE_KEYWORDS.has(seg));
}

function isConstrained(prop: JSONSchemaProperty): boolean {
  return (
    prop.pattern !== undefined ||
    prop.enum !== undefined ||
    prop.format !== undefined
  );
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
        if (
          prop.type === "string" &&
          matchesSensitiveKeyword(name) &&
          !isConstrained(prop)
        ) {
          findings.push({
            ruleId: "IV-001",
            pillar: "schema-integrity",
            severity: "high",
            title: `Unconstrained string on execution-adjacent field "${path}"`,
            detail:
              `Tool "${tool.name}" declares string property "${path}" whose name ` +
              `suggests it feeds a command, path, query, or network target, but the ` +
              `schema imposes no pattern, enum, or format constraint. A free-form ` +
              `string on an execution-adjacent field is a structural injection risk: ` +
              `the schema accepts any value a caller supplies.`,
            location: {
              file: ctx.file,
              jsonPath: `tools["${tool.name}"].inputSchema.properties.${path}`,
            },
            remediation:
              `Constrain "${path}" with a "pattern" (e.g. an allowlist regex), an ` +
              `"enum" of permitted values, or a "format" so the schema rejects ` +
              `arbitrary input instead of relying on the server to sanitize it.`,
            complianceRefs: [...COMPLIANCE_REFS],
          });
        }
      }, 0, state);
    } else if (matchesSensitiveKeyword(tool.name)) {
      findings.push({
        ruleId: "IV-002",
        pillar: "schema-integrity",
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
