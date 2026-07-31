/**
 * Compliance: scoring and report rendering for audit results.
 */
import type {
  AuditResult,
  AuditScore,
  Finding,
  LetterGrade,
  Pillar,
  Severity,
} from "./types.js";

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 50,
  high: 30,
  medium: 15,
  low: 5,
  info: 0,
};

/** Most severe first; lower index = more severe. */
export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/**
 * Start at 100 and subtract per-finding severity weights, dampened by
 * 1/sqrt(n) for the nth occurrence of the same ruleId so a single noisy
 * rule doesn't dominate the score. Clamped to [0, 100].
 */
export function computeScore(findings: Finding[]): AuditScore {
  const occurrences = new Map<string, number>();
  let penalty = 0;
  for (const finding of findings) {
    const n = (occurrences.get(finding.ruleId) ?? 0) + 1;
    occurrences.set(finding.ruleId, n);
    penalty += SEVERITY_WEIGHTS[finding.severity] / Math.sqrt(n);
  }
  const value = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  return { value, grade: toGrade(value) };
}

function toGrade(value: number): LetterGrade {
  if (value >= 90) return "A";
  if (value >= 75) return "B";
  if (value >= 60) return "C";
  if (value >= 40) return "D";
  return "F";
}

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/**
 * Invisible/bidi/tag/control code points that findings warn about must not
 * survive verbatim into the rendered report (a poisoned tool name would
 * otherwise smuggle them right back in front of the reader). Replace each
 * with a visible [U+XXXX] escape. Mirrors the text-sanitizer rule's
 * categories, minus ordinary \t \n \r.
 */
const SUSPICIOUS_CODE_POINTS = new RegExp(
  "[" +
    "\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F" + // C0 controls minus \t\n\r
    "\\u007F-\\u009F" + // DEL + C1 controls
    "\\u200B-\\u200D\\u2060\\uFEFF" + // zero-width/invisible
    "\\u202A-\\u202E\\u2066-\\u2069" + // bidi controls
    "\\uFE00-\\uFE0F" + // variation selectors
    "\\u{E0000}-\\u{E007F}" + // Unicode tag characters
    "]",
  "gu"
);

function escapeSuspicious(text: string): string {
  return text.replace(SUSPICIOUS_CODE_POINTS, (char) => {
    const cp = char.codePointAt(0) ?? 0;
    return `[U+${cp.toString(16).toUpperCase().padStart(4, "0")}]`;
  });
}

/**
 * Findings mapped to the OWASP MCP Top 10 carry refs starting with this
 * prefix. The list is still a Phase 3 beta, so reports say so rather than
 * presenting the mapping as stable. Only category names and IDs are cited —
 * OWASP's descriptive text is CC BY-NC-SA and is not reproduced here.
 */
const OWASP_REF_PREFIX = "OWASP MCP";

const OWASP_BETA_NOTE =
  "References beginning `OWASP MCP` map to the [OWASP MCP Top 10]" +
  "(https://owasp.org/www-project-mcp-top-10/), currently a **Phase 3 beta** — " +
  "its category names and IDs may still change before release. Only category " +
  "names and IDs are cited. References beginning `mcpguard:` are internal " +
  "categories with no OWASP MCP Top 10 equivalent.";

function renderFinding(finding: Finding): string {
  const lines: string[] = [];
  const location = finding.location.jsonPath
    ? `${finding.location.file} → \`${finding.location.jsonPath}\``
    : finding.location.file;
  lines.push(
    `### [${finding.severity.toUpperCase()}] ${finding.ruleId}: ${finding.title}`
  );
  lines.push("");
  lines.push(`- **Location:** ${location}`);
  if (finding.complianceRefs && finding.complianceRefs.length > 0) {
    lines.push(`- **Compliance:** ${finding.complianceRefs.join(", ")}`);
  }
  lines.push("");
  lines.push(finding.detail);
  if (finding.remediation) {
    lines.push("");
    lines.push(`**Remediation:** ${finding.remediation}`);
  }
  return lines.join("\n");
}

export function renderMarkdownReport(result: AuditResult): string {
  const lines: string[] = [];

  lines.push("# mcpguard audit report");
  lines.push("");
  lines.push(`- **Timestamp:** ${result.timestamp}`);
  lines.push(`- **Tools scanned:** ${result.toolsScanned}`);
  lines.push(`- **Servers scanned:** ${result.serversScanned}`);
  lines.push(`- **Score:** ${result.score.value}/100 (grade ${result.score.grade})`);
  lines.push("");

  lines.push("## Findings by severity");
  lines.push("");
  lines.push("| Severity | Count |");
  lines.push("| --- | --- |");
  for (const severity of SEVERITY_ORDER) {
    const count = result.findings.filter((f) => f.severity === severity).length;
    lines.push(`| ${severity} | ${count} |`);
  }
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("No findings. 🎉");
    lines.push("");
  } else {
    const byPillar = new Map<Pillar, Finding[]>();
    for (const finding of result.findings) {
      const group = byPillar.get(finding.pillar) ?? [];
      group.push(finding);
      byPillar.set(finding.pillar, group);
    }
    for (const [pillar, findings] of byPillar) {
      lines.push(`## Pillar: ${pillar}`);
      lines.push("");
      const sorted = [...findings].sort(
        (a, b) => severityRank(a.severity) - severityRank(b.severity)
      );
      for (const finding of sorted) {
        lines.push(renderFinding(finding));
        lines.push("");
      }
    }
  }

  const citesOwasp = result.findings.some((f) =>
    f.complianceRefs?.some((ref) => ref.startsWith(OWASP_REF_PREFIX))
  );
  if (citesOwasp) {
    lines.push("## About the compliance references");
    lines.push("");
    lines.push(OWASP_BETA_NOTE);
    lines.push("");
  }

  if (result.warnings.length > 0) {
    lines.push("## Discovery warnings");
    lines.push("");
    for (const warning of result.warnings) {
      lines.push(`- ${warning}`);
    }
    lines.push("");
  }

  return escapeSuspicious(lines.join("\n"));
}
