/**
 * SV: meta-validation of the inputSchema itself — malformed or nonsensical
 * JSON Schema that other rules (which assume well-formed schemas) may have
 * silently skipped over.
 */
import type { Finding, JSONSchemaProperty, MCPToolDefinition } from "../core/types.js";
import type { RuleContext, ToolRule } from "./index.js";

const COMPLIANCE_REFS = ["MCP-TOP10:A1-InjectionSurface"];

const VALID_TYPES = new Set([
  "string",
  "number",
  "integer",
  "boolean",
  "object",
  "array",
  "null",
]);

function isSchemaNode(value: unknown): value is JSONSchemaProperty {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Resolve a local JSON pointer ("#", "#/properties/x", …) against the schema root. */
function resolveLocalRef(root: JSONSchemaProperty, ref: string): unknown {
  if (ref === "#") return root;
  if (!ref.startsWith("#/")) return undefined; // external/non-local: not resolvable offline
  let node: unknown = root;
  for (const rawToken of ref.slice(2).split("/")) {
    const token = rawToken.replace(/~1/g, "/").replace(/~0/g, "~");
    if (typeof node !== "object" || node === null) return undefined;
    node = (node as Record<string, unknown>)[token];
  }
  return node;
}

export const schemaValidationRule: ToolRule = {
  id: "schema-validation",
  check(tool: MCPToolDefinition, ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const root = tool.inputSchema;
    if (!isSchemaNode(root)) return findings;

    const push = (
      ruleId: string,
      severity: Finding["severity"],
      title: string,
      detail: string,
      remediation: string,
      jsonPath: string
    ): void => {
      findings.push({
        ruleId,
        pillar: "schema-integrity",
        severity,
        title,
        detail,
        location: { file: ctx.file, jsonPath },
        remediation,
        complianceRefs: [...COMPLIANCE_REFS],
      });
    };

    const visit = (
      node: JSONSchemaProperty,
      path: string,
      ancestors: JSONSchemaProperty[]
    ): void => {
      if (typeof node.type === "string" && !VALID_TYPES.has(node.type)) {
        push(
          "SV-001",
          "high",
          `Invalid schema type "${node.type}" at "${path}"`,
          `Tool "${tool.name}" declares "type": "${node.type}", which is not a ` +
            `valid JSON Schema primitive type. Validators and other audit rules ` +
            `may silently skip this field because its type never matches, leaving ` +
            `it effectively unvalidated.`,
          `Correct "type" to one of: string, number, integer, boolean, object, ` +
            `array, null.`,
          path
        );
      }

      const hasProperties = isSchemaNode(node.properties);
      if (hasProperties && node.type !== "object") {
        push(
          "SV-002",
          "medium",
          `"properties" declared on a non-object node at "${path}"`,
          `Tool "${tool.name}" declares "properties" on a schema node whose ` +
            `"type" is ${node.type === undefined ? "missing" : `"${node.type}"`}. ` +
            `JSON Schema only applies "properties" to objects, so these ` +
            `declarations are dead weight and the author's intended constraints ` +
            `are not enforced.`,
          `Set "type": "object" on this node (or remove the stray "properties").`,
          path
        );
      }

      if (node.items !== undefined && node.type !== "array") {
        push(
          "SV-003",
          "medium",
          `"items" declared on a non-array node at "${path}"`,
          `Tool "${tool.name}" declares "items" on a schema node whose "type" is ` +
            `${node.type === undefined ? "missing" : `"${node.type}"`}. JSON ` +
            `Schema only applies "items" to arrays, so the item constraints are ` +
            `not enforced.`,
          `Set "type": "array" on this node (or remove the stray "items").`,
          path
        );
      }

      if (Array.isArray(node.required)) {
        const declared = hasProperties
          ? new Set(Object.keys(node.properties as Record<string, unknown>))
          : new Set<string>();
        const missing = node.required.filter(
          (name): name is string => typeof name === "string" && !declared.has(name)
        );
        if (missing.length > 0) {
          push(
            "SV-004",
            "medium",
            `"required" lists undeclared properties at "${path}"`,
            `Tool "${tool.name}" requires ${missing.map((m) => `"${m}"`).join(", ")} ` +
              `at "${path}", but no such propert${missing.length === 1 ? "y is" : "ies are"} ` +
              `declared in "properties". A required field that cannot be declared ` +
              `can never be satisfied, so every input either fails validation or ` +
              `the validator ignores the constraint.`,
            `Declare the missing propert${missing.length === 1 ? "y" : "ies"} in ` +
              `"properties", or remove the stale name(s) from "required".`,
            path
          );
        }
      }

      const ref = node["$ref"];
      if (typeof ref === "string") {
        const target = resolveLocalRef(root, ref);
        if (
          target !== undefined &&
          (target === node || ancestors.some((a) => a === target))
        ) {
          push(
            "SV-005",
            "high",
            `Cyclic $ref "${ref}" at "${path}"`,
            `Tool "${tool.name}" has a "$ref" at "${path}" that resolves back to ` +
              `the node itself or one of its ancestors. A naive parser or ` +
              `validator following this reference recurses forever.`,
            `Break the cycle: point the "$ref" at a non-ancestor definition, or ` +
              `inline the intended schema.`,
            path
          );
        }
      }

      const nextAncestors = [...ancestors, node];
      if (hasProperties) {
        for (const [name, child] of Object.entries(
          node.properties as Record<string, unknown>
        )) {
          if (isSchemaNode(child)) {
            visit(child, `${path}.properties.${name}`, nextAncestors);
          }
        }
      }
      if (isSchemaNode(node.items)) {
        visit(node.items, `${path}.items`, nextAncestors);
      }
    };

    visit(root, `tools["${tool.name}"].inputSchema`, []);
    return findings;
  },
};
