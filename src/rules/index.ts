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

export interface RuleContext {
  file: string;
}

export interface ToolRule {
  id: string;
  check(tool: MCPToolDefinition, ctx: RuleContext): Finding[];
}

export interface ServerRule {
  id: string;
  check(server: MCPServerConfig, ctx: RuleContext): Finding[];
}

export const toolRules: ToolRule[] = [inputValidationRule, textSanitizerRule];
export const serverRules: ServerRule[] = [networkBoundsRule];
