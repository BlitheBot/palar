/**
 * Rules: static checks run against discovered MCP definitions.
 * Each rule inspects parsed JSON structure and emits findings — nothing else.
 */
import type {
  Finding,
  MCPToolDefinition,
  MCPServerConfig,
} from "../core/types.js";
import { inputValidationRule } from "./input-validation.js";
import { textSanitizerRule } from "./text-sanitizer.js";
import { networkBoundsRule } from "./network-bounds.js";
import { schemaValidationRule } from "./schema-validation.js";

import type { ResolvedConfig } from "../core/config.js";

export interface RuleContext {
  file: string;
  /** Resolved configuration; rules fall back to built-in defaults when absent. */
  config?: ResolvedConfig;
  /** Collector for non-finding warnings (e.g. hardening-limit hits). */
  warn?: (message: string) => void;
}

export interface ToolRule {
  id: string;
  check(tool: MCPToolDefinition, ctx: RuleContext): Finding[];
}

export interface ServerRule {
  id: string;
  check(server: MCPServerConfig, ctx: RuleContext): Finding[];
}

export const toolRules: ToolRule[] = [
  inputValidationRule,
  textSanitizerRule,
  schemaValidationRule,
];
export const serverRules: ServerRule[] = [networkBoundsRule];
