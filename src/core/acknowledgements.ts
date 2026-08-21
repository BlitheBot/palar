/**
 * Acknowledgements: "yes, we know, that's intended."
 *
 * ## What problem this solves, and what it must not become
 *
 * palar had no way to express accepted risk, which made it unusable in CI
 * against a legitimately destructive server. desktop-commander's
 * `start_process` confirms command injection on every run — correctly; the
 * tool is a shell and execution is the product — and drives the grade to F
 * forever. Without acceptance the only options are "never run palar in CI"
 * or "ignore palar in CI", and both are worse than the problem.
 *
 * The thing this must not become is a suppression file: a place where
 * findings go to disappear. Three decisions keep it from being one, and
 * they are the whole design.
 *
 * ## 1. An accepted finding is not removed. It is not even discounted.
 *
 * Acceptance changes the EXIT CODE and nothing else. It does not touch the
 * score, the grade, the severity, the confidence, or membership in
 * `findings`. compliance.ts:146-149 already states the principle this
 * follows — the numeric score is left exactly as computed even when the
 * grade is clamped, because it ranks how much exposure was found and
 * rewriting it to agree with a verdict throws that away.
 *
 * The score answers *how much exposure is in this target*. Acceptance
 * answers *do we, this team, ship anyway*. Different questions, different
 * speakers. Folding the second into the first would mean a team that
 * accepts everything scores 100/A — a number that then goes in a README
 * badge and lies to everyone who never opens the report. desktop-commander
 * stays 0/F forever, which is true, and its build goes green, which is the
 * team's call to make.
 *
 * ## 2. confirmedForcesF() is untouched, and cannot be reached from here
 *
 * The clamp at compliance.ts:90-92 exists so palar never calls a
 * callback-proven defect a pass. Because acceptance does not operate on
 * grades at all, the clamp is not weakened, not bypassed, and not
 * consulted: a confirmed finding still grades F with any .palarrc.json
 * whatsoever.
 *
 * What acceptance can do is let the BUILD pass with an F on record. The
 * failure mode to prevent there is not acceptance — it is acceptance being
 * SILENT. So covering a confirmed finding requires `acceptsConfirmed: true`
 * written by a human, the report says so at full volume, and --json carries
 * it structurally so an org-level policy can refuse what one repo allowed.
 *
 * `acceptsConfirmed` is not redundant with naming `IV-101` directly,
 * because of the aliasing below: an entry written against static `IV-001`
 * would otherwise start covering a confirmed finding the first time
 * somebody runs `palar live`. The flag makes that transition require an
 * edit rather than a change of command.
 *
 * ## 3. Identity, and why it is (ruleId, jsonPath)
 *
 * An acknowledgement keyed on something unstable either stops matching
 * (annoying, fails safe) or matches the wrong thing (silent, fails unsafe).
 * Of what a Finding carries:
 *
 *   - `title` / `detail` are rewritten wholesale on escalation
 *     (live/escalate.ts) — keying on prose means a reworded message
 *     silently unmatches.
 *   - `severity` is user-mutable via `severityOverrides` (config.ts).
 *   - `confidence` changes on escalation.
 *   - `location.line` is declared but populated by no rule in the codebase.
 *
 * That leaves `ruleId` and `location.jsonPath`, and jsonPath is now
 * entirely property- and value-addressed: network-bounds.ts was the last
 * rule selecting by array index, and it now selects `exposedHosts["host"]`
 * by value precisely so an acknowledgement cannot be silently moved by a
 * reordered array.
 *
 * `file` is deliberately NOT part of the key by default. It is the least
 * stable component (repo layout, relative vs absolute, monorepo moves) and
 * jsonPath already carries `tools["name"]`. It is available as optional
 * narrowing for the case it exists to serve: two servers with a same-named
 * tool.
 *
 * `ruleId` matching consults the supersession chain (core/types.ts's
 * SupersededRuleIds), so an entry written against `IV-001` covers the
 * `IV-101` that same finding becomes once a callback proves it. Without
 * that, an acknowledgement would stop working at the exact moment the
 * finding it describes became most important.
 *
 * ## 4. Rot
 *
 * `reason` and `added` are required — the reason IS the product here, and
 * a date makes age computable. `expires` is optional in general, because a
 * hard expiry on everything teaches people to write `2099-01-01`; it is
 * REQUIRED for `acceptsConfirmed`, where indefinite silence on a proven
 * defect is worth a cliff, and capped so "required" cannot be satisfied by
 * a date a century out.
 *
 * Staleness is made visible rather than fatal: an entry with no expiry
 * warns once it passes STALE_AFTER_DAYS, and an entry with one warns
 * before it lapses rather than surprising a build at 3am.
 */
import type { AcceptedMark, AuditResult, Finding } from "./types.js";

/** An acknowledgement as written in .palarrc.json, after validation. */
export interface Acknowledgement {
  ruleId: string;
  jsonPath: string;
  /** Optional narrowing; when present the finding's file must match too. */
  file?: string;
  reason: string;
  /** ISO date (YYYY-MM-DD). */
  added: string;
  /** ISO date (YYYY-MM-DD). Required when acceptsConfirmed is true. */
  expires?: string;
  acceptsConfirmed?: boolean;
}

/** Days after `added` at which an acknowledgement with no expiry starts warning. */
export const STALE_AFTER_DAYS = 90;

/** Days before `expires` at which an acknowledgement starts warning. */
export const EXPIRY_WARNING_DAYS = 14;

/**
 * Maximum days between `added` and `expires` for a confirmed acceptance.
 *
 * Without a cap, "expiry is required for acceptsConfirmed" is satisfied by
 * writing a date in 2099, which is the same as no expiry while looking
 * like compliance. A year is long enough to be workable and short enough
 * that a proven defect gets re-examined within a plausible team lifetime.
 */
export const MAX_CONFIRMED_ACCEPTANCE_DAYS = 366;

const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

/** Parses YYYY-MM-DD as UTC midnight, or null when not a real date. */
export function parseIsoDate(value: string): Date | null {
  if (!ISO_DATE.test(value)) return null;
  const date = new Date(`${value}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return null;
  // Rejects 2026-02-31, which Date would otherwise roll into March.
  if (date.toISOString().slice(0, 10) !== value) return null;
  return date;
}

function daysBetween(from: Date, to: Date): number {
  return Math.round((to.getTime() - from.getTime()) / 86_400_000);
}

/**
 * Every rule id an acknowledgement may be written against to cover this
 * finding: its current id plus every id it previously carried.
 */
function identitiesOf(finding: Finding): string[] {
  return [finding.ruleId, ...(finding.supersedes ?? [])];
}

function matches(ack: Acknowledgement, finding: Finding): boolean {
  if (finding.location.jsonPath !== ack.jsonPath) return false;
  if (ack.file !== undefined && ack.file !== finding.location.file) return false;
  return identitiesOf(finding).includes(ack.ruleId);
}

/** Why an acknowledgement did not take effect, when it matched a finding but could not cover it. */
export interface AcknowledgementRefusal {
  ack: Acknowledgement;
  finding: Finding;
  reason: string;
}

/**
 * An acknowledgement that matched no finding in this run.
 *
 * `possibleMove` is the difference between "you fixed it" and "it is still
 * there under a new name", which is the entire question a reader has when
 * they see a stale entry. A renamed tool moves every jsonPath beneath it at
 * once, so this is usually the actual explanation.
 */
export interface UnmatchedAcknowledgement {
  ack: Acknowledgement;
  possibleMove?: { jsonPath: string; ruleId: string };
}

export interface AcknowledgementOutcome {
  result: AuditResult;
  /** Findings that were accepted, in report order. */
  accepted: Finding[];
  unmatched: UnmatchedAcknowledgement[];
  refusals: AcknowledgementRefusal[];
  /** Human-readable warnings: staleness, imminent expiry, lapsed expiry. */
  warnings: string[];
}

/**
 * Rule ids that only exist after a live run.
 *
 * An acknowledgement naming one of these can never match during
 * `palar scan`, because the rewrite that produces them happens in
 * live/escalate.ts. Reporting those as stale on every static run would
 * train people to ignore the unmatched-acknowledgement warning, which
 * destroys the one mechanism that catches genuinely rotten entries — so
 * they are held quiet unless the run actually had a live pass.
 */
export const LIVE_ONLY_RULE_IDS = new Set(["IV-101", "TA-101"]);

export interface ApplyOptions {
  /** True when this run included a live pass; gates LIVE_ONLY_RULE_IDS reporting. */
  live?: boolean;
  /** Injectable for tests; defaults to now. */
  now?: Date;
}


/**
 * True when two paths differ ONLY in the name inside their leading
 * `tools["..."]` / `servers["..."]` segment.
 *
 * This is the renamed-subject test behind the "possible move" hint. It
 * deliberately refuses the looser "same rule, different path" reading,
 * which fires on every sibling instance of a rule that can match more than
 * once per file and turns a useful hint into noise.
 */
export function isRenamedSubject(a: string, b: string): boolean {
  const SUBJECT = /^((?:tools|servers)\[")([^"]+)("\].*)$/;
  const ma = SUBJECT.exec(a);
  const mb = SUBJECT.exec(b);
  if (!ma || !mb) return false;
  // Same collection, different name, identical remainder.
  return ma[1] === mb[1] && ma[2] !== mb[2] && ma[3] === mb[3];
}

/**
 * Applies acknowledgements to a finished audit result.
 *
 * Called AFTER escalation, never before: escalate.ts rewrites ruleIds and
 * appends findings, and an acknowledgement pass that ran first would be
 * matching against ids that are about to change.
 *
 * Returns a new result whose accepted findings carry an `accepted` mark.
 * The findings array, every severity, every confidence and the score are
 * otherwise untouched — see the module docstring on why that is the
 * design and not an oversight.
 */
export function applyAcknowledgements(
  result: AuditResult,
  acknowledgements: Acknowledgement[],
  opts: ApplyOptions = {}
): AcknowledgementOutcome {
  const now = opts.now ?? new Date();
  const warnings: string[] = [];
  const refusals: AcknowledgementRefusal[] = [];
  const accepted: Finding[] = [];
  const used = new Set<Acknowledgement>();

  const findings = result.findings.map((finding) => {
    const ack = acknowledgements.find((candidate) => matches(candidate, finding));
    if (!ack) return finding;

    // Matched. From here the entry is "used" even if it cannot cover the
    // finding — it is pointing at something real, so it is not stale, and
    // reporting it as both refused AND unmatched would be two complaints
    // about one entry.
    used.add(ack);

    if (finding.confidence === "confirmed" && ack.acceptsConfirmed !== true) {
      refusals.push({
        ack,
        finding,
        reason:
          `this finding is CONFIRMED (palar sent a payload and an out-of-band callback came ` +
          `back), and the acknowledgement does not set "acceptsConfirmed": true. Accepting ` +
          `proven, live-demonstrated behaviour has to be written down deliberately — add ` +
          `"acceptsConfirmed": true and an "expires" date if that is what you mean.`,
      });
      return finding;
    }

    const expiry = ack.expires ? parseIsoDate(ack.expires) : null;
    if (expiry && daysBetween(now, expiry) < 0) {
      refusals.push({
        ack,
        finding,
        reason:
          `the acknowledgement expired on ${ack.expires} (${-daysBetween(now, expiry)} day(s) ` +
          `ago), so it no longer applies. This is not a new problem — it is an accepted one ` +
          `whose acceptance lapsed.`,
      });
      return finding;
    }

    const mark: AcceptedMark = {
      reason: ack.reason,
      added: ack.added,
      ...(ack.expires ? { expires: ack.expires } : {}),
      ...(ack.acceptsConfirmed ? { acceptsConfirmed: true } : {}),
      ...(expiry ? { daysUntilExpiry: daysBetween(now, expiry) } : {}),
    };
    const marked: Finding = { ...finding, accepted: mark };
    accepted.push(marked);
    return marked;
  });

  // Staleness and imminent expiry, for entries that actually applied.
  for (const ack of acknowledgements) {
    if (!used.has(ack)) continue;
    const expiry = ack.expires ? parseIsoDate(ack.expires) : null;
    if (expiry) {
      const left = daysBetween(now, expiry);
      if (left >= 0 && left <= EXPIRY_WARNING_DAYS) {
        warnings.push(
          `acknowledgement for ${ack.ruleId} at ${ack.jsonPath} expires in ${left} day(s) ` +
            `(${ack.expires}) — after that this finding gates again`
        );
      }
      continue;
    }
    const added = parseIsoDate(ack.added);
    if (added) {
      const age = daysBetween(added, now);
      if (age > STALE_AFTER_DAYS) {
        warnings.push(
          `acknowledgement for ${ack.ruleId} at ${ack.jsonPath} was written ${age} day(s) ago ` +
            `(${ack.added}) and has no "expires" — accepted risk that is never revisited is ` +
            `how a suppression file rots. Re-confirm it or set an expiry.`
        );
      }
    }
  }

  const unmatched: UnmatchedAcknowledgement[] = [];
  for (const ack of acknowledgements) {
    if (used.has(ack)) continue;
    // Mode-aware quieting: an IV-101 entry cannot match in a static run.
    if (!opts.live && LIVE_ONLY_RULE_IDS.has(ack.ruleId)) continue;
    // Fixed, or moved?
    //
    // "Same ruleId at some other path" is too loose to be useful: NB-004
    // fires once per private host, so an entry for a host that was deleted
    // would point at an unrelated host and call it a move. The signature
    // of an actual move is narrower — a RENAMED SUBJECT: two paths whose
    // leading `tools["X"]` / `servers["X"]` segment differs and whose
    // remainder is identical. That is exactly what renaming a tool does to
    // every path beneath it, and it does not fire for sibling instances of
    // a repeated rule.
    const moved = result.findings.find(
      (f) =>
        identitiesOf(f).includes(ack.ruleId) &&
        f.location.jsonPath !== undefined &&
        f.location.jsonPath !== ack.jsonPath &&
        isRenamedSubject(ack.jsonPath, f.location.jsonPath)
    );
    unmatched.push({
      ack,
      ...(moved && moved.location.jsonPath
        ? { possibleMove: { jsonPath: moved.location.jsonPath, ruleId: moved.ruleId } }
        : {}),
    });
  }

  return {
    // Score deliberately NOT recomputed: nothing that feeds it changed.
    result: { ...result, findings },
    accepted,
    unmatched,
    refusals,
    warnings,
  };
}
