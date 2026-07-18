/**
 * Discovery: locates local MCP tool and server definition JSON files on disk.
 * Read-only — filesystem access only, never the network.
 */
import { readFile, stat } from "node:fs/promises";
import fg from "fast-glob";
import type { MCPToolDefinition, MCPServerConfig } from "../core/types.js";
import { DEFAULT_LIMITS } from "../core/config.js";

export interface DiscoverOptions {
  /** Max file size in bytes; larger matched files are skipped with a warning. */
  maxFileSize?: number;
}

export interface DiscoveredFiles {
  tools: { file: string; definition: MCPToolDefinition }[];
  servers: { file: string; config: MCPServerConfig }[];
  /** Files that were matched but skipped (unreadable, malformed JSON, wrong shape). */
  warnings: string[];
}

const TOOL_PATTERNS = [
  "**/mcp.tools.json",
  "**/tools/*.json",
  "**/*.mcp-tools.json",
];

const SERVER_PATTERNS = [
  "**/mcp.server.json",
  "**/mcp.config.json",
  "**/*.mcp-server.json",
];

const IGNORE_PATTERNS = [
  "**/node_modules/**",
  "**/dist/**",
  "**/.git/**",
  "**/examples/**",
];

async function findFiles(patterns: string[], roots: string[]): Promise<string[]> {
  const matched = new Set<string>();
  for (const root of roots) {
    const files = await fg(patterns, {
      cwd: root,
      ignore: IGNORE_PATTERNS,
      absolute: true,
      onlyFiles: true,
      // A read-only scanner should not be lured outside the scanned root
      // by a symlinked directory.
      followSymbolicLinks: false,
    });
    for (const file of files) matched.add(file);
  }
  return [...matched].sort();
}

/**
 * Read and parse a matched JSON file, normalizing a single object or an
 * array of objects to an array. Returns null (with a warning collected)
 * on read errors, malformed JSON, or a non-object payload.
 */
async function parseEntries(
  file: string,
  warnings: string[],
  maxFileSize: number
): Promise<Record<string, unknown>[] | null> {
  // Check size via stat before reading so oversized files are never
  // loaded into memory at all.
  try {
    const info = await stat(file);
    if (info.size > maxFileSize) {
      warnings.push(
        `${file}: skipped — file size ${info.size} bytes exceeds the ` +
          `${maxFileSize}-byte limit (override with --max-file-size)`
      );
      return null;
    }
  } catch (err) {
    warnings.push(`${file}: unreadable (${(err as Error).message})`);
    return null;
  }

  let raw: string;
  try {
    raw = await readFile(file, "utf8");
  } catch (err) {
    warnings.push(`${file}: unreadable (${(err as Error).message})`);
    return null;
  }

  let parsed: unknown;
  try {
    // Tolerate a UTF-8 BOM — common in Windows-authored JSON, rejected by JSON.parse.
    parsed = JSON.parse(raw.replace(/^﻿/, ""));
  } catch (err) {
    warnings.push(`${file}: malformed JSON (${(err as Error).message})`);
    return null;
  }

  const entries = Array.isArray(parsed) ? parsed : [parsed];
  const objects: Record<string, unknown>[] = [];
  for (const entry of entries) {
    if (typeof entry === "object" && entry !== null && !Array.isArray(entry)) {
      objects.push(entry as Record<string, unknown>);
    } else {
      warnings.push(`${file}: skipped a non-object entry`);
    }
  }
  return objects;
}

export async function discover(
  paths: string[],
  options: DiscoverOptions = {}
): Promise<DiscoveredFiles> {
  const maxFileSize = options.maxFileSize ?? DEFAULT_LIMITS.maxFileSize;
  const roots = paths.length > 0 ? paths : [process.cwd()];
  const result: DiscoveredFiles = { tools: [], servers: [], warnings: [] };

  const [toolFiles, serverFiles] = await Promise.all([
    findFiles(TOOL_PATTERNS, roots),
    findFiles(SERVER_PATTERNS, roots),
  ]);

  const serverFileSet = new Set(serverFiles);
  for (const file of toolFiles) {
    if (serverFileSet.has(file)) {
      result.warnings.push(
        `${file}: matched both tool and server patterns; audited as both a ` +
          `tool and a server config`
      );
    }
  }

  for (const file of toolFiles) {
    const entries = await parseEntries(file, result.warnings, maxFileSize);
    if (!entries) continue;
    for (const entry of entries) {
      if (typeof entry.name !== "string") {
        result.warnings.push(`${file}: skipped a tool entry with no "name" string`);
        continue;
      }
      result.tools.push({ file, definition: entry as unknown as MCPToolDefinition });
    }
  }

  // A duplicate tool name is a plausible impersonation/shadowing vector:
  // one definition can silently override or coexist with another.
  const filesByToolName = new Map<string, string[]>();
  for (const { file, definition } of result.tools) {
    const files = filesByToolName.get(definition.name) ?? [];
    files.push(file);
    filesByToolName.set(definition.name, files);
  }
  for (const [name, files] of filesByToolName) {
    if (files.length > 1) {
      result.warnings.push(
        `duplicate tool name "${name}" declared ${files.length} times in: ${files.join(", ")}`
      );
    }
  }

  for (const file of serverFiles) {
    const entries = await parseEntries(file, result.warnings, maxFileSize);
    if (!entries) continue;
    for (const entry of entries) {
      if (typeof entry.name !== "string") {
        result.warnings.push(`${file}: skipped a server entry with no "name" string`);
        continue;
      }
      result.servers.push({ file, config: entry as unknown as MCPServerConfig });
    }
  }

  return result;
}
