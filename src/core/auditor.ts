/**
 * Auditor: runs every registered rule against every discovered definition
 * and assembles the AuditResult.
 */
import type { AuditResult, Finding } from "./types.js";
import type { DiscoveredFiles } from "../discovery/index.js";
import type { ResolvedConfig } from "./config.js";
import { DEFAULT_CONFIG } from "./config.js";
import { toolRules, serverRules } from "../rules/index.js";
import { computeScore } from "./compliance.js";

export function runAudit(
  discovered: DiscoveredFiles,
  config: ResolvedConfig = DEFAULT_CONFIG
): AuditResult {
  const findings: Finding[] = [];
  const warnings = [...discovered.warnings];
  const warn = (message: string): void => {
    warnings.push(message);
  };

  for (const { file, definition } of discovered.tools) {
    for (const rule of toolRules) {
      findings.push(...rule.check(definition, { file, config, warn }));
    }
  }

  for (const { file, config: serverConfig } of discovered.servers) {
    for (const rule of serverRules) {
      findings.push(...rule.check(serverConfig, { file, config, warn }));
    }
  }

  // Apply config-driven per-ruleId severity overrides before scoring, so
  // a downgraded rule also weighs less in the score.
  const overrides = config.severityOverrides ?? {};
  const finalFindings = findings.map((finding) => {
    const override = overrides[finding.ruleId];
    return override ? { ...finding, severity: override } : finding;
  });

  return {
    timestamp: new Date().toISOString(),
    toolsScanned: discovered.tools.length,
    serversScanned: discovered.servers.length,
    findings: finalFindings,
    score: computeScore(finalFindings),
    warnings,
  };
}
