/**
 * Auditor: runs every registered rule against every discovered definition
 * and assembles the AuditResult.
 */
import type { AuditResult, Finding } from "./types.js";
import type { DiscoveredFiles } from "../discovery/index.js";
import { toolRules, serverRules } from "../rules/index.js";
import { computeScore } from "./compliance.js";

export function runAudit(discovered: DiscoveredFiles): AuditResult {
  const findings: Finding[] = [];

  for (const { file, definition } of discovered.tools) {
    for (const rule of toolRules) {
      findings.push(...rule.check(definition, { file }));
    }
  }

  for (const { file, config } of discovered.servers) {
    for (const rule of serverRules) {
      findings.push(...rule.check(config, { file }));
    }
  }

  return {
    timestamp: new Date().toISOString(),
    toolsScanned: discovered.tools.length,
    serversScanned: discovered.servers.length,
    findings,
    score: computeScore(findings),
    warnings: [...discovered.warnings],
  };
}
