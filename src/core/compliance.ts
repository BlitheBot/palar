/**
 * Compliance: scoring and report rendering for audit results.
 */
import type {
  AuditResult,
  AuditScore,
  Confidence,
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

/**
 * How much of a finding's severity weight actually lands, by confidence.
 *
 * Severity says how bad a finding is IF real; this says how much palar
 * established that it is. They multiply, and the multiplier is not a
 * rescaling of severity — a medium hypothesis and a medium observation are
 * genuinely different claims, and before this existed they cost the same.
 *
 * The numbers, and why each is what it is:
 *
 *   - `hypothesized` at 0.25. A field-name heuristic should move a grade,
 *     because it is worth looking at, but it must not decide one. Eleven of
 *     them (server-filesystem) cost ~20 points and twenty cost ~28 — but the
 *     1/sqrt(n) dampening sums to 2*sqrt(n), which grows without bound, so
 *     around 65 of them would still reach F on the arithmetic alone. That is
 *     the same error this axis exists to fix, just needing more findings to
 *     trigger, which is why hypothesisOnlyFloor() exists.
 *   - `observed` at 0.6. The defect is really there in the artifact, so it
 *     is not a guess — but "there in the file" is still not "reached at
 *     runtime", and a declared `exposedHosts` entry is a statement of
 *     intent rather than a demonstrated route.
 *   - `confirmed` at 1.25, i.e. ABOVE full weight. Evidence outranks
 *     inference, and this is the only class palar has that rests on a
 *     callback it received rather than a string it read.
 *
 * A confirmed finding always yields grade F — see confirmedForcesF() and
 * computeScore(), where that is an explicit rule rather than a consequence
 * of these three numbers.
 */
const CONFIDENCE_MULTIPLIERS: Record<Confidence, number> = {
  confirmed: 1.25,
  observed: 0.6,
  hypothesized: 0.25,
};

/** Most severe first; lower index = more severe. */
export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Strongest evidence first, for report ordering and breakdown tables. */
export const CONFIDENCE_ORDER: Confidence[] = [
  "confirmed",
  "observed",
  "hypothesized",
];

/**
 * Whether the grade is forced to F regardless of the numeric score.
 *
 * Stated as its own rule on purpose, and NOT left to fall out of the
 * arithmetic. With today's three numbers it happens to be redundant: a
 * confirmed finding is always critical, and 50 x 1.25 = 62.5 already
 * exceeds the 60 points that separate F from D. But that is an emergent
 * property of three constants that live in three different places, and the
 * way it breaks is silent — the day palar grows a confirmed finding class
 * that is not `critical` (a confirmed information disclosure at `high`, say:
 * 30 x 1.25 = 37.5, which grades C), a callback-proven defect would quietly
 * start passing a `C`-threshold gate.
 *
 * So the guarantee is written down where it can be tested directly:
 * anything palar watched happen is a settled result, and a settled result
 * is not a matter of degree.
 */
function confirmedForcesF(findings: Finding[]): boolean {
  return findings.some((finding) => finding.confidence === "confirmed");
}

/**
 * The mirror of confirmedForcesF(): inference alone cannot produce an F.
 *
 * F is a "do not ship this" verdict, and palar should not issue one on the
 * strength of findings that, by their own text, are guesses about code it
 * never read. That is the same discipline that makes it refuse to score a
 * target it never examined — and the two rules are deliberately symmetric:
 *
 *   evidence can force the worst grade; inference cannot.
 *
 * Without this the multiplier only postpones the problem it was introduced
 * to fix. 0.25 keeps eleven unverified mediums (server-filesystem) at a B,
 * but the per-rule dampening sums to 2*sqrt(n) rather than converging, so
 * ~65 of them land back in F with nothing having been demonstrated about
 * any of them. No server in the sample is near that; a large enough
 * generated tool surface would be.
 *
 * D rather than C as the floor: a pile of unverified execution-adjacent
 * fields IS a large attack surface and the grade should say so loudly. It
 * just must not say "proven bad", which is what F means once CONFIRMED
 * exists as a category.
 *
 * Applies only when EVERY finding is hypothesized. One observed finding —
 * a real credential in the file, a real bidi override — is a fact, and
 * facts are allowed to carry a result to F on their own.
 */
function hypothesisOnlyFloor(findings: Finding[]): boolean {
  return (
    findings.length > 0 && findings.every((finding) => finding.confidence === "hypothesized")
  );
}

/**
 * Start at 100 and subtract per-finding severity weight scaled by
 * confidence, dampened by 1/sqrt(n) for the nth occurrence of the same
 * ruleId so a single noisy rule doesn't dominate. Clamped to [0, 100].
 *
 * The dampening stays keyed on ruleId alone rather than on (ruleId,
 * confidence): a rule's confidence is a property of the rule, so the pair
 * would never differ within one ruleId today, and keying on it would
 * quietly change the dampening the day it did.
 */
export function computeScore(findings: Finding[]): AuditScore {
  const occurrences = new Map<string, number>();
  let penalty = 0;
  for (const finding of findings) {
    const n = (occurrences.get(finding.ruleId) ?? 0) + 1;
    occurrences.set(finding.ruleId, n);
    penalty +=
      (SEVERITY_WEIGHTS[finding.severity] * CONFIDENCE_MULTIPLIERS[finding.confidence]) /
      Math.sqrt(n);
  }
  const value = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  // The numeric score is left exactly as computed even when the grade is
  // clamped in either direction. It still ranks how much total exposure was
  // found, which is information a reader wants, and rewriting it to agree
  // with the letter would throw that away.
  //
  // Order matters only in the sense that the two clamps are mutually
  // exclusive by construction: a result cannot both contain a confirmed
  // finding and consist entirely of hypothesized ones.
  if (confirmedForcesF(findings)) return { value, grade: "F" };
  const grade = toGrade(value);
  if (grade === "F" && hypothesisOnlyFloor(findings)) return { value, grade: "D" };
  return { value, grade };
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
  "names and IDs are cited. References beginning `palar:` are internal " +
  "categories with no OWASP MCP Top 10 equivalent.";

/** How each confidence reads in a heading — short, and not jargon. */
const CONFIDENCE_LABELS: Record<Confidence, string> = {
  confirmed: "CONFIRMED",
  observed: "OBSERVED",
  hypothesized: "UNVERIFIED",
};

/** One line each, so the breakdown table explains itself without the docs. */
const CONFIDENCE_BLURBS: Record<Confidence, string> = {
  confirmed:
    "palar sent a payload and an out-of-band callback carrying that probe's nonce came back. " +
    "Settled, not inferred.",
  observed:
    "the defect is present in the definition palar read — the characters, the credential, the " +
    "declared host are really there. Not a guess, but also not a demonstrated runtime route.",
  hypothesized:
    "inferred from a field's name and shape. palar did not see this value reach anything, and " +
    "cannot from a file alone. Worth looking at; not a demonstrated defect.",
};

/**
 * The acceptance note attached to a finding wherever it is rendered.
 *
 * Deliberately not quiet. An accepted finding is one somebody decided to
 * ship with, and the report's job is to make that decision legible to the
 * next person — the reason, who dated it, and when it lapses. A confirmed
 * acceptance says so at full volume, because "we are shipping a defect
 * palar proved by callback" is the single most consequential sentence this
 * tool can print.
 */
function renderAcceptance(finding: Finding): string[] {
  const mark = finding.accepted;
  if (!mark) return [];
  const lines: string[] = [];
  lines.push(`- **Accepted:** ${mark.reason}`);
  const expiry =
    mark.expires === undefined
      ? "no expiry set"
      : `expires ${mark.expires}` +
        (mark.daysUntilExpiry === undefined ? "" : ` (${mark.daysUntilExpiry} day(s) away)`);
  lines.push(`- **Acknowledged:** ${mark.added} · ${expiry}`);
  if (mark.acceptsConfirmed) {
    lines.push("");
    lines.push(
      "  **This is a CONFIRMED finding that the project has accepted.** palar sent a payload " +
        "and an out-of-band callback carrying that probe's nonce came back — this behaviour " +
        "was demonstrated, not inferred. The build passes because `.palarrc.json` accepts it. " +
        "**The grade is still F**, and acceptance did not change the score, the severity, or " +
        "the confidence: it changed only whether the build fails."
    );
  }
  return lines;
}

/**
 * The ACCEPTED roll-up.
 *
 * Placed above the pillar sections rather than below them: a reader
 * scanning a report with a failing grade and a passing build needs to know
 * why before they read anything else, and burying the explanation under
 * the findings is how "the build is green, ignore the F" becomes folklore.
 */
function renderAcceptedSection(result: AuditResult): string[] {
  const accepted = result.findings.filter((f) => f.accepted);
  if (accepted.length === 0) return [];
  const confirmed = accepted.filter((f) => f.confidence === "confirmed").length;
  const lines: string[] = [];
  lines.push("## ACCEPTED — known, and shipped anyway");
  lines.push("");
  lines.push(
    `${accepted.length} finding(s) are acknowledged in this project's configuration` +
      (confirmed > 0 ? `, ${confirmed} of them CONFIRMED` : "") +
      `. They are still counted, still scored, and still listed below with their full ` +
      `severity — acceptance changes only whether the build fails, never what palar found. ` +
      `The grade above is unaffected.`
  );
  lines.push("");
  lines.push("| Rule | Location | Reason | Since | Expires |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const f of accepted) {
    const mark = f.accepted!;
    const cell = (text: string): string => escapeSuspicious(text).replace(/\|/g, "\\|");
    lines.push(
      `| ${f.ruleId}${f.confidence === "confirmed" ? " · **CONFIRMED**" : ""} ` +
        `| \`${cell(f.location.jsonPath ?? f.location.file)}\` | ${cell(mark.reason)} ` +
        `| ${mark.added} | ${mark.expires ?? "—"} |`
    );
  }
  lines.push("");
  return lines;
}

function renderFinding(finding: Finding): string {
  const lines: string[] = [];
  const location = finding.location.jsonPath
    ? `${finding.location.file} → \`${finding.location.jsonPath}\``
    : finding.location.file;
  // Confidence sits in the heading next to severity, not buried in a
  // detail line. The pair is the claim — "[MEDIUM] this might reach a
  // shell" and "[MEDIUM] this key is in your file" are different sentences,
  // and a reader skimming headings has to be able to tell them apart.
  lines.push(
    `### [${finding.severity.toUpperCase()} · ${CONFIDENCE_LABELS[finding.confidence]}` +
      `${finding.accepted ? " · ACCEPTED" : ""}] ${finding.ruleId}: ${finding.title}`
  );
  lines.push("");
  lines.push(`- **Location:** ${location}`);
  // In the heading AND inline, because the pillar sections are where a
  // reader actually reads findings — an ACCEPTED section elsewhere is a
  // summary, not a substitute for the finding saying so where it lives.
  lines.push(...renderAcceptance(finding));
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

  lines.push("# palar audit report");
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

  // Printed alongside severity rather than instead of it, because the two
  // together are what the score is made of. A reader who sees 80/B on
  // eleven findings should be able to see, in one table, that all eleven
  // are unverified — that is the explanation for the grade, and without it
  // the number looks arbitrary.
  lines.push("## Findings by confidence");
  lines.push("");
  lines.push(
    "What palar established, as distinct from how bad it would be. Severity and confidence " +
      "are independent, and the score multiplies them: an unverified finding moves the grade " +
      "a little, a confirmed one settles it."
  );
  lines.push("");
  lines.push("| Confidence | Count | What it means |");
  lines.push("| --- | --- | --- |");
  for (const confidence of CONFIDENCE_ORDER) {
    const count = result.findings.filter((f) => f.confidence === confidence).length;
    lines.push(
      `| ${CONFIDENCE_LABELS[confidence]} | ${count} | ${CONFIDENCE_BLURBS[confidence]} |`
    );
  }
  lines.push("");
  if (result.findings.some((f) => f.confidence === "confirmed")) {
    lines.push(
      "**This grade is F because something was CONFIRMED.** That is a rule, not an artefact " +
        "of the arithmetic: palar watched this happen, and a settled result is not a matter " +
        "of degree. The numeric score still ranks total exposure."
    );
    lines.push("");
  }

  lines.push(...renderAcceptedSection(result));

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
