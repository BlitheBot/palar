/**
 * Discovery: locates local MCP tool and server definition JSON files on disk.
 * Read-only — filesystem access only, never the network.
 */
import { readFile, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";
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

/**
 * Splits the given roots into directories to glob and files named
 * outright, warning about anything that is neither.
 *
 * --help has always documented "files or directories to scan", and files
 * did not work: fast-glob takes a root as its `cwd`, and handing it a file
 * made it throw a raw `ENOTDIR: not a directory, scandir <path>` that
 * escaped to the CLI's top-level catch and printed as an errno. Worse, it
 * printed and then exited 0 — a documented invocation crashing and
 * reporting success.
 *
 * A path that does not exist is reported here rather than swallowed for
 * the same reason `--fail-on-empty` exists: a moved or mistyped scan path
 * should be visible, not silently indistinguishable from a directory that
 * happens to contain nothing.
 */
async function partitionRoots(
  roots: string[],
  warnings: string[]
): Promise<{ dirs: string[]; files: string[] }> {
  const dirs: string[] = [];
  const files: string[] = [];
  for (const root of roots) {
    let info;
    try {
      info = await stat(root);
    } catch (err) {
      warnings.push(`${root}: cannot be scanned (${(err as Error).message})`);
      continue;
    }
    if (info.isDirectory()) dirs.push(root);
    // Absolute and POSIX-separated, which is the form fast-glob returns for
    // `absolute: true` on every platform. Without matching it, the same file
    // reached by name and by globbing its directory are two different
    // strings on Windows ("C:\\x\\mcp.tools.json" vs "C:/x/mcp.tools.json")
    // and the deduplicating Set below lets both through — so every tool in
    // that file gets audited twice and reported as a duplicate of itself.
    else if (info.isFile()) files.push(resolve(root).split(sep).join("/"));
    else warnings.push(`${root}: not a file or directory, skipped`);
  }
  return { dirs, files };
}

/**
 * Whether one path segment matches one glob segment.
 *
 * Deliberately not a general glob implementation: `*` and literals are the
 * only constructs TOOL_PATTERNS and SERVER_PATTERNS use inside a segment,
 * and keeping this to exactly those is what makes having a second matcher
 * in the file defensible at all. The alternative was reaching into
 * fast-glob's own matcher through a transitive dependency, which is not
 * ours to depend on.
 */
function segmentMatches(value: string, pattern: string): boolean {
  const source = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, "[^/]*");
  return new RegExp(`^${source}$`).test(value);
}

/**
 * Whether a POSIX-separated path matches one of this module's own patterns.
 * Each is a globstar prefix followed by one or two literal segments, so the
 * prefix is dropped and the remaining segments are matched against the tail
 * of the path.
 */
function matchesPattern(posixPath: string, pattern: string): boolean {
  const rest = pattern.startsWith("**/") ? pattern.slice(3) : pattern;
  const segments = rest.split("/");
  const pathSegments = posixPath.split("/");
  if (pathSegments.length < segments.length) return false;
  const tail = pathSegments.slice(pathSegments.length - segments.length);
  return segments.every((segment, i) => segmentMatches(tail[i]!, segment));
}

/**
 * Which bucket(s) an explicitly named file belongs in — neither, when its
 * name matches no MCP definition pattern at all.
 *
 * Naming a file on the command line is not enough on its own to make an
 * arbitrary JSON file scannable, and the reason is that palar would
 * otherwise have to guess. The two rule sets are different (tool
 * definitions vs. server configs), nothing in a bare JSON object reliably
 * separates them, and running the wrong one produces confident findings
 * about the wrong thing. So the existing patterns still decide which
 * analyser a file gets, and a file matching neither is refused by name
 * rather than analysed on a hunch.
 *
 * A file CAN be both, exactly as it can when found by globbing a directory.
 */
function classifyNamedFile(posixPath: string): { tool: boolean; server: boolean } {
  return {
    tool: TOOL_PATTERNS.some((p) => matchesPattern(posixPath, p)),
    server: SERVER_PATTERNS.some((p) => matchesPattern(posixPath, p)),
  };
}

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

  // Directories get globbed; files named outright are taken as given. See
  // partitionRoots() for why this split exists rather than every root being
  // handed to fast-glob as a `cwd`.
  const { dirs, files: namedFiles } = await partitionRoots(roots, result.warnings);

  const namedTools: string[] = [];
  const namedServers: string[] = [];
  for (const file of namedFiles) {
    const kind = classifyNamedFile(file);
    if (kind.tool) namedTools.push(file);
    if (kind.server) namedServers.push(file);
    if (!kind.tool && !kind.server) {
      result.warnings.push(
        `${file}: named on the command line but its name matches no MCP definition pattern ` +
          `(${[...TOOL_PATTERNS, ...SERVER_PATTERNS].map((p) => p.replace("**/", "")).join(", ")}), ` +
          `so palar cannot tell whether it declares tools or a server and did not read it. ` +
          `Rename it to match, or point palar at the directory containing it.`
      );
    }
  }

  const [globbedTools, globbedServers] = await Promise.all([
    findFiles(TOOL_PATTERNS, dirs),
    findFiles(SERVER_PATTERNS, dirs),
  ]);
  const toolFiles = [...new Set([...globbedTools, ...namedTools])].sort();
  const serverFiles = [...new Set([...globbedServers, ...namedServers])].sort();

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
