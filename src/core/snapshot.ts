/**
 * Snapshot: hashes tool definitions into a baseline and diffs baselines
 * against the current state to detect drift (rug-pull style redefinition
 * of a tool after it was reviewed). v2 snapshots also store a bounded
 * structural summary per tool — property paths with their scalar
 * constraints, enum counts, and description length — so drift can report
 * WHAT changed and whether it loosened security-relevant constraints.
 */
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import type {
  JSONSchemaProperty,
  MCPToolDefinition,
  PropertySummary,
  SchemaSnapshot,
  ToolSnapshotEntry,
} from "./types.js";
import type { DiscoveredFiles } from "../discovery/index.js";
import type { HardeningLimits } from "./config.js";
import { DEFAULT_LIMITS } from "./config.js";

export interface SnapshotDiffEntry {
  toolName: string;
  kind: "added" | "removed" | "changed";
}

export type ChangeClassification = "tightening" | "loosening" | "neutral";

export interface SemanticChange {
  /** Property path the change applies to, or "" for tool-level changes. */
  path: string;
  description: string;
  classification: ChangeClassification;
}

export interface ToolDiffEntry {
  toolName: string;
  /** "regressed" = changed with at least one loosening change. */
  kind: "added" | "removed" | "changed" | "regressed";
  changes: SemanticChange[];
  /** For regressed tools: what loosened, joined into one line. */
  reason?: string;
}

interface CanonicalizeState {
  depthExceeded: boolean;
}

/**
 * Serialize a JSON value with object keys sorted at every level, so two
 * definitions that differ only in key order hash identically. Depth is
 * capped so a maliciously deep definition cannot overflow the stack;
 * content beyond the cap is replaced with a marker (and flagged), which
 * still hashes deterministically.
 */
function canonicalize(
  value: unknown,
  depth: number,
  maxDepth: number,
  state: CanonicalizeState
): string {
  if (depth > maxDepth) {
    state.depthExceeded = true;
    return '"__palar_depth_limit__"';
  }
  if (Array.isArray(value)) {
    return `[${value
      .map((v) => canonicalize(v, depth + 1, maxDepth, state))
      .join(",")}]`;
  }
  if (typeof value === "object" && value !== null) {
    const entries = Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalize(
            (value as Record<string, unknown>)[key],
            depth + 1,
            maxDepth,
            state
          )}`
      );
    return `{${entries.join(",")}}`;
  }
  // JSON.stringify(undefined) is undefined, not a string.
  return JSON.stringify(value) ?? "null";
}

const SCALAR_CONSTRAINT_KEYS = [
  "pattern",
  "format",
  "minLength",
  "maxLength",
  "minimum",
  "maximum",
  "minItems",
  "maxItems",
] as const;

function isSchemaNode(value: unknown): value is JSONSchemaProperty {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function summarizeProperties(
  definition: MCPToolDefinition,
  limits: HardeningLimits
): Record<string, PropertySummary> {
  const summaries: Record<string, PropertySummary> = {};

  const walk = (
    properties: Record<string, unknown>,
    parentPath: string,
    requiredNames: Set<string>,
    depth: number
  ): void => {
    if (depth > limits.maxNestingDepth) return;
    for (const [name, prop] of Object.entries(properties)) {
      if (!isSchemaNode(prop)) continue;
      const path = parentPath === "" ? name : `${parentPath}.${name}`;
      const summary: PropertySummary = {
        required: requiredNames.has(name),
        constraints: {},
      };
      const rawType: unknown = prop.type;
      if (
        typeof rawType === "string" ||
        (Array.isArray(rawType) && rawType.every((t) => typeof t === "string"))
      ) {
        summary.type = rawType as string | string[];
      }
      for (const key of SCALAR_CONSTRAINT_KEYS) {
        const value = (prop as Record<string, unknown>)[key];
        if (typeof value === "string" || typeof value === "number") {
          summary.constraints[key] = value;
        }
      }
      if (Array.isArray(prop.enum)) {
        summary.constraints["enumCount"] = prop.enum.length;
      }
      summaries[path] = summary;

      if (isSchemaNode(prop.properties)) {
        const childRequired = new Set(
          Array.isArray(prop.required)
            ? prop.required.filter((r): r is string => typeof r === "string")
            : []
        );
        walk(
          prop.properties as Record<string, unknown>,
          path,
          childRequired,
          depth + 1
        );
      }
      if (isSchemaNode(prop.items)) {
        walk({ [`${name}[]`]: prop.items }, parentPath, new Set(), depth + 1);
      }
    }
  };

  const schema = definition.inputSchema;
  if (isSchemaNode(schema) && isSchemaNode(schema.properties)) {
    const rootRequired = new Set(
      Array.isArray(schema.required)
        ? schema.required.filter((r): r is string => typeof r === "string")
        : []
    );
    walk(schema.properties as Record<string, unknown>, "", rootRequired, 0);
  }
  return summaries;
}

export interface BuildSnapshotResult {
  snapshot: SchemaSnapshot;
  /** Name collisions detected while keying tools by name. */
  warnings: string[];
}

export function buildSnapshot(
  discovered: DiscoveredFiles,
  limits: HardeningLimits = DEFAULT_LIMITS
): BuildSnapshotResult {
  const tools: Record<string, ToolSnapshotEntry> = {};
  const sourceFile: Record<string, string> = {};
  const warnings: string[] = [];
  for (const { file, definition } of discovered.tools) {
    const state: CanonicalizeState = { depthExceeded: false };
    const canonical = canonicalize(
      {
        name: definition.name,
        description: definition.description,
        inputSchema: definition.inputSchema,
      },
      0,
      limits.maxNestingDepth,
      state
    );
    if (state.depthExceeded) {
      warnings.push(
        `${file}: tool "${definition.name}": schema nesting depth limit ` +
          `(${limits.maxNestingDepth}) reached while hashing; content beyond ` +
          `the limit was replaced with a marker`
      );
    }
    if (definition.name in tools) {
      warnings.push(
        `duplicate tool name "${definition.name}": definition from ${file} ` +
          `overrides the one from ${sourceFile[definition.name]} in this snapshot`
      );
    }
    tools[definition.name] = {
      hash: createHash("sha256").update(canonical, "utf8").digest("hex"),
      descriptionLength:
        typeof definition.description === "string"
          ? definition.description.length
          : 0,
      properties: summarizeProperties(definition, limits),
    };
    sourceFile[definition.name] = file;
  }
  return {
    snapshot: { snapshotVersion: 2, createdAt: new Date().toISOString(), tools },
    warnings,
  };
}

/** Returns null on a missing, unreadable, or malformed snapshot file. */
export async function loadSnapshot(path: string): Promise<SchemaSnapshot | null> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.replace(/^﻿/, ""));
  } catch {
    return null;
  }
  if (
    typeof parsed !== "object" ||
    parsed === null ||
    typeof (parsed as SchemaSnapshot).createdAt !== "string" ||
    typeof (parsed as SchemaSnapshot).tools !== "object" ||
    (parsed as SchemaSnapshot).tools === null
  ) {
    return null;
  }
  for (const value of Object.values((parsed as SchemaSnapshot).tools)) {
    const isLegacyHash = typeof value === "string";
    const isEntry =
      typeof value === "object" &&
      value !== null &&
      typeof (value as ToolSnapshotEntry).hash === "string";
    if (!isLegacyHash && !isEntry) return null;
  }
  return parsed as SchemaSnapshot;
}

export async function saveSnapshot(
  path: string,
  snapshot: SchemaSnapshot
): Promise<void> {
  await writeFile(path, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
}

function hashOf(entry: ToolSnapshotEntry | string): string {
  return typeof entry === "string" ? entry : entry.hash;
}

/** Hash-level diff (added/removed/changed); works on v1 and v2 snapshots. */
export function diffSnapshots(
  baseline: SchemaSnapshot,
  current: SchemaSnapshot
): SnapshotDiffEntry[] {
  const diff: SnapshotDiffEntry[] = [];
  for (const [toolName, entry] of Object.entries(current.tools)) {
    const baseEntry = baseline.tools[toolName];
    if (baseEntry === undefined) {
      diff.push({ toolName, kind: "added" });
    } else if (hashOf(baseEntry) !== hashOf(entry)) {
      diff.push({ toolName, kind: "changed" });
    }
  }
  for (const toolName of Object.keys(baseline.tools)) {
    if (!(toolName in current.tools)) {
      diff.push({ toolName, kind: "removed" });
    }
  }
  return diff;
}

/** Direction of "value increased" per numeric constraint. */
const INCREASE_LOOSENS = new Set(["maxLength", "maximum", "maxItems", "enumCount"]);
const INCREASE_TIGHTENS = new Set(["minLength", "minimum", "minItems"]);

function constraintLabel(key: string): string {
  return key === "enumCount" ? "enum" : key;
}

function compareEntries(
  base: ToolSnapshotEntry,
  cur: ToolSnapshotEntry
): SemanticChange[] {
  const changes: SemanticChange[] = [];

  if (base.descriptionLength !== cur.descriptionLength) {
    // A large growth gives injected instructions room to hide; treat as
    // loosening when it more than doubles AND exceeds the 1000-char
    // description-hygiene threshold. Otherwise a wording-level change.
    const loosened =
      cur.descriptionLength > base.descriptionLength * 2 &&
      cur.descriptionLength > 1000;
    changes.push({
      path: "",
      description: `description length changed from ${base.descriptionLength} to ${cur.descriptionLength} characters`,
      classification: loosened ? "loosening" : "neutral",
    });
  }

  const allPaths = new Set([
    ...Object.keys(base.properties),
    ...Object.keys(cur.properties),
  ]);
  for (const path of [...allPaths].sort()) {
    const b = base.properties[path];
    const c = cur.properties[path];
    if (b === undefined && c !== undefined) {
      changes.push({
        path,
        description: `parameter "${path}" added`,
        classification: "neutral",
      });
      continue;
    }
    if (b !== undefined && c === undefined) {
      changes.push({
        path,
        description: `parameter "${path}" removed`,
        classification: "neutral",
      });
      continue;
    }
    if (b === undefined || c === undefined) continue;

    if (b.required === true && c.required !== true) {
      changes.push({
        path,
        description: `required flag removed from parameter "${path}"`,
        classification: "loosening",
      });
    } else if (b.required !== true && c.required === true) {
      changes.push({
        path,
        description: `parameter "${path}" made required`,
        classification: "tightening",
      });
    }

    if (JSON.stringify(b.type) !== JSON.stringify(c.type)) {
      changes.push({
        path,
        description: `type of parameter "${path}" changed from ${JSON.stringify(b.type)} to ${JSON.stringify(c.type)}`,
        classification: "neutral",
      });
    }

    const keys = new Set([
      ...Object.keys(b.constraints),
      ...Object.keys(c.constraints),
    ]);
    for (const key of [...keys].sort()) {
      const bv = b.constraints[key];
      const cv = c.constraints[key];
      const label = constraintLabel(key);
      if (bv === undefined && cv !== undefined) {
        changes.push({
          path,
          description: `${label} added to parameter "${path}"`,
          classification: "tightening",
        });
      } else if (bv !== undefined && cv === undefined) {
        changes.push({
          path,
          description: `${label} removed from parameter "${path}"`,
          classification: "loosening",
        });
      } else if (bv !== cv) {
        if (typeof bv === "number" && typeof cv === "number") {
          const increased = cv > bv;
          const loosens = increased
            ? INCREASE_LOOSENS.has(key)
            : INCREASE_TIGHTENS.has(key);
          const description =
            key === "enumCount"
              ? `enum ${increased ? "expanded" : "narrowed"} from ${bv} to ${cv} values on parameter "${path}"`
              : `${label} changed from ${bv} to ${cv} on parameter "${path}"`;
          changes.push({
            path,
            description,
            classification: loosens ? "loosening" : "tightening",
          });
        } else {
          changes.push({
            path,
            description: `${label} changed on parameter "${path}"`,
            classification: "neutral",
          });
        }
      }
    }
  }
  return changes;
}

/**
 * Semantic diff: hash-level added/removed/changed plus, for v2 entries on
 * both sides, per-tool structural changes classified as tightening,
 * loosening, or neutral. A changed tool with any loosening change is
 * reported as "regressed" with a reason. Legacy v1 entries degrade to a
 * bare "changed" with no detail.
 */
export function diffSnapshotsDetailed(
  baseline: SchemaSnapshot,
  current: SchemaSnapshot
): ToolDiffEntry[] {
  const result: ToolDiffEntry[] = [];
  for (const entry of diffSnapshots(baseline, current)) {
    if (entry.kind !== "changed") {
      result.push({ ...entry, changes: [] });
      continue;
    }
    const base = baseline.tools[entry.toolName];
    const cur = current.tools[entry.toolName];
    if (typeof base === "string" || typeof cur === "string" || !base || !cur) {
      result.push({ ...entry, changes: [] });
      continue;
    }
    const changes = compareEntries(base, cur);
    const loosenings = changes.filter((c) => c.classification === "loosening");
    if (loosenings.length > 0) {
      result.push({
        toolName: entry.toolName,
        kind: "regressed",
        changes,
        reason: loosenings.map((c) => c.description).join("; "),
      });
    } else {
      result.push({ toolName: entry.toolName, kind: "changed", changes });
    }
  }
  return result;
}
