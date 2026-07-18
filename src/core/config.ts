/**
 * Configuration: hardening limits plus tunable rule inputs, loadable from
 * an optional .mcpguardrc.json (or --config <path>). With no config file
 * present, behavior is identical to the built-in defaults.
 */
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Severity } from "./types.js";

export interface HardeningLimits {
  /** Max definition file size in bytes; larger files are skipped with a warning. */
  maxFileSize: number;
  /** Max schema nesting depth rules will walk; deeper branches are skipped with a warning. */
  maxNestingDepth: number;
  /** Max schema nodes visited per tool per rule; the walk stops with a warning beyond this. */
  maxSchemaNodes: number;
}

export const DEFAULT_LIMITS: HardeningLimits = {
  maxFileSize: 10 * 1024 * 1024,
  maxNestingDepth: 50,
  maxSchemaNodes: 5000,
};

export type UnicodeCategoryName =
  | "zeroWidth"
  | "bidi"
  | "tagChars"
  | "variationSelectors"
  | "controlChars";

export interface NetworkPatterns {
  /** Exact host names treated as loopback (compared lowercased). */
  loopbackHosts: string[];
  /** Regex sources matched against normalized hosts for loopback. */
  loopbackPatterns: string[];
  /** Regex sources matched against normalized hosts for private/link-local space. */
  privateSubnetPatterns: string[];
}

/** Fully-resolved configuration passed to rules via RuleContext. */
export interface ResolvedConfig {
  limits: HardeningLimits;
  /** Keyword segments input-validation treats as execution-adjacent. */
  sensitiveKeywords: string[];
  /** Hex code-point ranges ("200B" or "200B-200D") per text-sanitizer category. */
  unicodeCategories: Record<UnicodeCategoryName, string[]>;
  network: NetworkPatterns;
  /** Per-ruleId severity overrides applied to every emitted finding. */
  severityOverrides: Record<string, Severity>;
}

export const DEFAULT_CONFIG: ResolvedConfig = {
  limits: { ...DEFAULT_LIMITS },
  sensitiveKeywords: [
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
  ],
  unicodeCategories: {
    zeroWidth: ["200B-200D", "2060", "FEFF"],
    bidi: ["202A-202E", "2066-2069"],
    tagChars: ["E0000-E007F"],
    variationSelectors: ["FE00-FE0F"],
    controlChars: ["0000-0008", "000B-000C", "000E-001F", "007F-009F"],
  },
  network: {
    loopbackHosts: ["localhost", "0.0.0.0", "::1"],
    loopbackPatterns: ["^127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"],
    privateSubnetPatterns: [
      "^10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$",
      "^192\\.168\\.\\d{1,3}\\.\\d{1,3}$",
      "^172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}$",
      "^169\\.254\\.\\d{1,3}\\.\\d{1,3}$",
    ],
  },
  severityOverrides: {},
};

export const CONFIG_FILE_NAME = ".mcpguardrc.json";

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const KNOWN_TOP_LEVEL_KEYS = new Set([
  "configVersion",
  "limits",
  "sensitiveKeywords",
  "unicodeCategories",
  "network",
  "severityOverrides",
]);
const CODE_POINT_RANGE = /^[0-9a-fA-F]{1,6}(-[0-9a-fA-F]{1,6})?$/;

/** Parse hex range strings ("200B", "200B-200D") into [lo, hi] pairs. */
export function parseCodePointRanges(ranges: string[]): [number, number][] {
  return ranges.map((r) => {
    const [loRaw, hiRaw] = r.split("-");
    const lo = parseInt(loRaw ?? "", 16);
    const hi = hiRaw !== undefined ? parseInt(hiRaw, 16) : lo;
    return [lo, hi];
  });
}

function fail(source: string, problem: string): never {
  throw new Error(`invalid config${source ? ` at ${source}` : ""}: ${problem}`);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function requireStringArray(v: unknown, field: string, source: string): string[] {
  if (!Array.isArray(v) || v.some((s) => typeof s !== "string" || s.length === 0)) {
    fail(source, `"${field}" must be an array of non-empty strings`);
  }
  return v as string[];
}

function requireRegexArray(v: unknown, field: string, source: string): string[] {
  const arr = requireStringArray(v, field, source);
  for (const pattern of arr) {
    try {
      new RegExp(pattern);
    } catch {
      fail(source, `"${field}" contains an invalid regular expression: ${pattern}`);
    }
  }
  return arr;
}

/**
 * Validate a raw parsed config object and merge it over the defaults.
 * Throws a descriptive Error on any shape problem — a malformed config
 * must never be silently ignored.
 */
export function resolveConfig(raw?: unknown, source = ""): ResolvedConfig {
  if (raw === undefined) {
    return structuredClone(DEFAULT_CONFIG);
  }
  if (!isPlainObject(raw)) {
    fail(source, "top level must be a JSON object");
  }
  if (raw.configVersion !== 1) {
    fail(
      source,
      `"configVersion" is required and must be 1 (got ${JSON.stringify(raw.configVersion)})`
    );
  }
  const unknown = Object.keys(raw).filter((k) => !KNOWN_TOP_LEVEL_KEYS.has(k));
  if (unknown.length > 0) {
    fail(source, `unknown key(s): ${unknown.join(", ")}`);
  }

  const config = structuredClone(DEFAULT_CONFIG);

  if (raw.limits !== undefined) {
    if (!isPlainObject(raw.limits)) fail(source, `"limits" must be an object`);
    for (const [key, value] of Object.entries(raw.limits)) {
      if (!(key in DEFAULT_LIMITS)) {
        fail(source, `"limits" has unknown key "${key}"`);
      }
      if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
        fail(source, `"limits.${key}" must be a positive integer`);
      }
      config.limits[key as keyof HardeningLimits] = value;
    }
  }

  if (raw.sensitiveKeywords !== undefined) {
    config.sensitiveKeywords = requireStringArray(
      raw.sensitiveKeywords,
      "sensitiveKeywords",
      source
    ).map((k) => k.toLowerCase());
  }

  if (raw.unicodeCategories !== undefined) {
    if (!isPlainObject(raw.unicodeCategories)) {
      fail(source, `"unicodeCategories" must be an object`);
    }
    for (const [key, value] of Object.entries(raw.unicodeCategories)) {
      if (!(key in config.unicodeCategories)) {
        fail(
          source,
          `"unicodeCategories" has unknown category "${key}" (valid: ` +
            `${Object.keys(config.unicodeCategories).join(", ")})`
        );
      }
      const ranges = requireStringArray(value, `unicodeCategories.${key}`, source);
      for (const r of ranges) {
        if (!CODE_POINT_RANGE.test(r)) {
          fail(
            source,
            `"unicodeCategories.${key}" contains "${r}" — expected hex code ` +
              `points like "200B" or ranges like "200B-200D"`
          );
        }
      }
      config.unicodeCategories[key as UnicodeCategoryName] = ranges;
    }
  }

  if (raw.network !== undefined) {
    if (!isPlainObject(raw.network)) fail(source, `"network" must be an object`);
    for (const key of Object.keys(raw.network)) {
      if (!(key in config.network)) {
        fail(source, `"network" has unknown key "${key}"`);
      }
    }
    if (raw.network.loopbackHosts !== undefined) {
      config.network.loopbackHosts = requireStringArray(
        raw.network.loopbackHosts,
        "network.loopbackHosts",
        source
      ).map((h) => h.toLowerCase());
    }
    if (raw.network.loopbackPatterns !== undefined) {
      config.network.loopbackPatterns = requireRegexArray(
        raw.network.loopbackPatterns,
        "network.loopbackPatterns",
        source
      );
    }
    if (raw.network.privateSubnetPatterns !== undefined) {
      config.network.privateSubnetPatterns = requireRegexArray(
        raw.network.privateSubnetPatterns,
        "network.privateSubnetPatterns",
        source
      );
    }
  }

  if (raw.severityOverrides !== undefined) {
    if (!isPlainObject(raw.severityOverrides)) {
      fail(source, `"severityOverrides" must be an object of ruleId -> severity`);
    }
    for (const [ruleId, severity] of Object.entries(raw.severityOverrides)) {
      if (typeof severity !== "string" || !VALID_SEVERITIES.has(severity)) {
        fail(
          source,
          `"severityOverrides.${ruleId}" must be one of: critical, high, ` +
            `medium, low, info (got ${JSON.stringify(severity)})`
        );
      }
      config.severityOverrides[ruleId] = severity as Severity;
    }
  }

  return config;
}

/**
 * Load configuration for a CLI run. An explicit path must exist and parse;
 * otherwise .mcpguardrc.json in searchDir is used when present; otherwise
 * defaults. Throws a descriptive Error on missing explicit path or any
 * malformed config.
 */
export async function loadConfigFile(
  explicitPath: string | undefined,
  searchDir: string
): Promise<ResolvedConfig> {
  let path: string;
  if (explicitPath !== undefined) {
    path = explicitPath;
  } else {
    path = join(searchDir, CONFIG_FILE_NAME);
  }

  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch (err) {
    if (explicitPath !== undefined) {
      throw new Error(
        `config file not found or unreadable at ${explicitPath} (${(err as Error).message})`
      );
    }
    return structuredClone(DEFAULT_CONFIG);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw.replace(/^﻿/, ""));
  } catch (err) {
    throw new Error(`invalid config at ${path}: malformed JSON (${(err as Error).message})`);
  }
  return resolveConfig(parsed, path);
}
