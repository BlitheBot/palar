/**
 * Configuration: hardening limits that protect mcpguard itself from
 * hostile or degenerate input files.
 */

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

/** Fully-resolved configuration passed to rules via RuleContext. */
export interface ResolvedConfig {
  limits: HardeningLimits;
}

export const DEFAULT_CONFIG: ResolvedConfig = {
  limits: { ...DEFAULT_LIMITS },
};
