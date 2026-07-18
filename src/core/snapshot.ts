/**
 * Snapshot: hashes tool definitions into a baseline and diffs baselines
 * against the current state to detect drift (rug-pull style redefinition
 * of a tool after it was reviewed).
 */
import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import type { SchemaSnapshot } from "./types.js";
import type { DiscoveredFiles } from "../discovery/index.js";
import type { HardeningLimits } from "./config.js";
import { DEFAULT_LIMITS } from "./config.js";

export interface SnapshotDiffEntry {
  toolName: string;
  kind: "added" | "removed" | "changed";
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
    return '"__mcpguard_depth_limit__"';
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

export interface BuildSnapshotResult {
  snapshot: SchemaSnapshot;
  /** Name collisions detected while keying tools by name. */
  warnings: string[];
}

export function buildSnapshot(
  discovered: DiscoveredFiles,
  limits: HardeningLimits = DEFAULT_LIMITS
): BuildSnapshotResult {
  const tools: Record<string, string> = {};
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
    tools[definition.name] = createHash("sha256")
      .update(canonical, "utf8")
      .digest("hex");
    sourceFile[definition.name] = file;
  }
  return { snapshot: { createdAt: new Date().toISOString(), tools }, warnings };
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
  return parsed as SchemaSnapshot;
}

export async function saveSnapshot(
  path: string,
  snapshot: SchemaSnapshot
): Promise<void> {
  await writeFile(path, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
}

export function diffSnapshots(
  baseline: SchemaSnapshot,
  current: SchemaSnapshot
): SnapshotDiffEntry[] {
  const diff: SnapshotDiffEntry[] = [];
  for (const [toolName, hash] of Object.entries(current.tools)) {
    const baseHash = baseline.tools[toolName];
    if (baseHash === undefined) {
      diff.push({ toolName, kind: "added" });
    } else if (baseHash !== hash) {
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
