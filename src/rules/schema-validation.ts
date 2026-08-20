/**
 * SV: meta-validation of the inputSchema itself — malformed or nonsensical
 * JSON Schema that other rules (which assume well-formed schemas) may have
 * silently skipped over.
 */
import type { Finding, JSONSchemaProperty, MCPToolDefinition } from "../core/types.js";
import type { RuleContext, ToolRule } from "./index.js";
import { DEFAULT_LIMITS } from "../core/config.js";

const COMPLIANCE_REFS = ["OWASP MCP05:2025 - Command Injection & Execution"];

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

/** Declared type(s) as a string list, or null when absent/unusable. */
function declaredTypes(type: unknown): string[] | null {
  if (typeof type === "string") return [type];
  if (Array.isArray(type)) {
    const strings = type.filter((t): t is string => typeof t === "string");
    return strings.length > 0 ? strings : null;
  }
  return null;
}

function valueMatchesType(value: unknown, t: string): boolean {
  switch (t) {
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    case "array":
      return Array.isArray(value);
    case "object":
      return typeof value === "object" && value !== null && !Array.isArray(value);
    default:
      return false;
  }
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" ? value : undefined;
}

/** Short, safe rendering of an enum value for finding details. */
function showValue(value: unknown): string {
  const s = JSON.stringify(value) ?? "undefined";
  return s.length > 40 ? `${s.slice(0, 37)}...` : s;
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
        // Every SV-* finding is a property of the schema document itself —
        // a malformed type, a contradictory bound, a required key that is
        // not declared. palar read the schema and the defect is in it, so
        // this helper can fix the confidence for all of them rather than
        // taking it as a parameter. A future SV rule that inferred runtime
        // behaviour would need its own push site, which is the intended
        // friction.
        confidence: "observed",
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

      // --- Semantic contradiction checks (SV-006..SV-011): shapes that are
      // valid JSON Schema but logically impossible or inconsistent. ---

      const minLength = asNumber(node.minLength);
      const maxLength = asNumber(node.maxLength);
      if (minLength !== undefined && maxLength !== undefined && minLength > maxLength) {
        push(
          "SV-006",
          "medium",
          `minLength exceeds maxLength at "${path}"`,
          `Tool "${tool.name}" declares minLength (${minLength}) greater than ` +
            `maxLength (${maxLength}) — this constraint can never be satisfied, ` +
            `so every input fails validation (or the validator ignores it).`,
          `Make minLength <= maxLength, or remove whichever bound is wrong.`,
          path
        );
      }

      const minimum = asNumber(node.minimum);
      const maximum = asNumber(node.maximum);
      if (minimum !== undefined && maximum !== undefined && minimum > maximum) {
        push(
          "SV-007",
          "medium",
          `minimum exceeds maximum at "${path}"`,
          `Tool "${tool.name}" declares minimum (${minimum}) greater than ` +
            `maximum (${maximum}) — no number satisfies both bounds.`,
          `Make minimum <= maximum, or remove whichever bound is wrong.`,
          path
        );
      }
      const minItems = asNumber(node.minItems);
      const maxItems = asNumber(node.maxItems);
      if (minItems !== undefined && maxItems !== undefined && minItems > maxItems) {
        push(
          "SV-007",
          "medium",
          `minItems exceeds maxItems at "${path}"`,
          `Tool "${tool.name}" declares minItems (${minItems}) greater than ` +
            `maxItems (${maxItems}) — no array length satisfies both bounds.`,
          `Make minItems <= maxItems, or remove whichever bound is wrong.`,
          path
        );
      }

      const types = declaredTypes(rawType);
      if (types !== null) {
        const numericLike = types.some((t) => t === "number" || t === "integer");
        if (!numericLike && (node.minimum !== undefined || node.maximum !== undefined)) {
          push(
            "SV-008",
            "medium",
            `Numeric constraint on non-numeric type at "${path}"`,
            `Tool "${tool.name}" declares minimum/maximum on a node whose type ` +
              `is ${describeType(rawType)}. Numeric bounds only apply to ` +
              `number/integer, so this constraint is never enforced.`,
            `Change the type to number or integer, or remove the numeric bound.`,
            path
          );
        }
        const stringLike = types.includes("string");
        const stringConstraints = ["pattern", "minLength", "maxLength", "format"]
          .filter((k) => (node as Record<string, unknown>)[k] !== undefined);
        if (!stringLike && stringConstraints.length > 0) {
          push(
            "SV-009",
            "medium",
            `String constraint on non-string type at "${path}"`,
            `Tool "${tool.name}" declares ${stringConstraints.join(", ")} on a ` +
              `node whose type is ${describeType(rawType)}. String constraints ` +
              `only apply to strings, so they are never enforced.`,
            `Change the type to string, or remove the string constraint(s).`,
            path
          );
        }
      }

      if (Array.isArray(node.enum)) {
        if (types !== null) {
          const mismatched = node.enum.filter(
            (v) => !types.some((t) => valueMatchesType(v, t))
          );
          if (mismatched.length > 0) {
            push(
              "SV-010",
              "medium",
              `enum values do not match declared type at "${path}"`,
              `Tool "${tool.name}" declares type ${describeType(rawType)} but ` +
                `the enum contains ${mismatched.map(showValue).join(", ")}, ` +
                `which do not match that type — those values can never validate.`,
              `Align the enum values with the declared type (or fix the type).`,
              path
            );
          }
        }
        if (node.enum.length === 0) {
          push(
            "SV-011",
            "medium",
            `Empty enum at "${path}"`,
            `Tool "${tool.name}" declares an enum with zero entries — no value ` +
              `can ever satisfy it, so every input fails validation here.`,
            `Add the permitted values to the enum, or remove it.`,
            path
          );
        } else {
          const seen = new Set<string>();
          const duplicates = new Set<string>();
          for (const v of node.enum) {
            const key = JSON.stringify(v) ?? "undefined";
            if (seen.has(key)) duplicates.add(key);
            seen.add(key);
          }
          if (duplicates.size > 0) {
            push(
              "SV-011",
              "medium",
              `Duplicate enum values at "${path}"`,
              `Tool "${tool.name}" declares an enum with duplicate value(s): ` +
                `${[...duplicates].join(", ")}. Duplicates are dead entries that ` +
                `usually indicate a copy-paste or generation error.`,
              `Remove the duplicate enum entries.`,
              path
            );
          }
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
