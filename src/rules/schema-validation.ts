/**
 * SV: meta-validation of the inputSchema itself — malformed or nonsensical
 * JSON Schema that other rules (which assume well-formed schemas) may have
 * silently skipped over.
 */
import type { Finding, JSONSchemaProperty, MCPToolDefinition } from "../core/types.js";
import type { RuleContext, ToolRule } from "./index.js";
import { DEFAULT_LIMITS } from "../core/config.js";

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

/** True when "type" (string or union-array form) includes the wanted type. */
function typeIncludes(type: unknown, wanted: string): boolean {
  return type === wanted || (Array.isArray(type) && type.includes(wanted));
}

/** Every declared type value that is not a valid JSON Schema primitive. */
function invalidTypeValues(type: unknown): string[] {
  if (typeof type === "string") {
    return VALID_TYPES.has(type) ? [] : [type];
  }
  if (Array.isArray(type)) {
    return type
      .filter((t) => typeof t !== "string" || !VALID_TYPES.has(t))
      .map((t) => String(t));
  }
  return [];
}

function describeType(type: unknown): string {
  if (type === undefined) return "missing";
  return Array.isArray(type) ? JSON.stringify(type) : `"${String(type)}"`;
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

    const limits = ctx.config?.limits ?? DEFAULT_LIMITS;
    let nodesVisited = 0;
    let depthHit = false;
    let nodesHit = false;

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
      if (ancestors.length > limits.maxNestingDepth) {
        depthHit = true;
        return;
      }
      if (nodesVisited >= limits.maxSchemaNodes) {
        nodesHit = true;
        return;
      }
      nodesVisited += 1;
      const rawType: unknown = node.type;
      const invalid = invalidTypeValues(rawType);
      if (invalid.length > 0) {
        push(
          "SV-001",
          "high",
          `Invalid schema type ${invalid.map((t) => `"${t}"`).join(", ")} at "${path}"`,
          `Tool "${tool.name}" declares "type" ${describeType(rawType)}, which ` +
            `contains ${invalid.length === 1 ? "a value that is" : "values that are"} ` +
            `not valid JSON Schema primitive types. Validators and other audit ` +
            `rules may silently skip this field because its type never matches, ` +
            `leaving it effectively unvalidated.`,
          `Correct "type" to use only: string, number, integer, boolean, object, ` +
            `array, null.`,
          path
        );
      }

      const hasProperties = isSchemaNode(node.properties);
      if (hasProperties && !typeIncludes(rawType, "object")) {
        push(
          "SV-002",
          "medium",
          `"properties" declared on a non-object node at "${path}"`,
          `Tool "${tool.name}" declares "properties" on a schema node whose ` +
            `"type" is ${describeType(rawType)}. JSON Schema only applies ` +
            `"properties" to objects, so these declarations are dead weight and ` +
            `the author's intended constraints are not enforced.`,
          `Set "type": "object" (or include "object" in the type array) on this ` +
            `node, or remove the stray "properties".`,
          path
        );
      }

      if (node.items !== undefined && !typeIncludes(rawType, "array")) {
        push(
          "SV-003",
          "medium",
          `"items" declared on a non-array node at "${path}"`,
          `Tool "${tool.name}" declares "items" on a schema node whose "type" is ` +
            `${describeType(rawType)}. JSON Schema only applies "items" to ` +
            `arrays, so the item constraints are not enforced.`,
          `Set "type": "array" (or include "array" in the type array) on this ` +
            `node, or remove the stray "items".`,
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

      // Known limitation: only cycles through the walk path are detected
      // (a $ref resolving to the node itself or an ancestor). Indirect
      // cycles between sibling definitions (A -> B -> A where neither is
      // an ancestor of the other) are not followed.
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

    if (depthHit) {
      ctx.warn?.(
        `${ctx.file}: tool "${tool.name}": schema nesting depth limit ` +
          `(${limits.maxNestingDepth}) reached; deeper schema branches were ` +
          `not analyzed by schema-validation`
      );
    }
    if (nodesHit) {
      ctx.warn?.(
        `${ctx.file}: tool "${tool.name}": schema node limit ` +
          `(${limits.maxSchemaNodes}) reached; remaining schema was not ` +
          `analyzed by schema-validation`
      );
    }

    return findings;
  },
};
