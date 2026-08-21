/**
 * Probe coverage: how much of what palar set out to test it actually
 * tested, and what that means for the exit code.
 *
 * ## Why this is a module rather than four lines in the CLI action
 *
 * The rule it encodes is the same one `scan`'s never-reached path encodes
 * and the same one liveScan.ts's pessimistic `outcome` default encodes: a
 * run that examined nothing must not exit 0 alongside a run that examined
 * everything and found it clean. That rule was previously written inline
 * inside the `live` action handler, where it could not be tested without
 * running the whole CLI — so the one behaviour that decides a CI gate was
 * the least directly covered thing in the package.
 *
 * ## What counts as coverage
 *
 * A probe exercised its field unless it is `not-tested` or `inconclusive`.
 * Those two have opposite causes — palar's own invalid arguments for the
 * first, a tool that could not run in this environment for the second —
 * but they share the only property that matters here: the payload never
 * reached the field, so nothing was learned about it in either direction
 * and the static finding on it is exactly as unsettled as before the scan.
 *
 * `rejected` and `unconfirmed` DO count. They are real observations of the
 * target answering (or not answering) a payload that reached it. Neither
 * is a clean bill of health — status.ts is emphatic about that — but both
 * are things palar saw, which is the distinction this module draws.
 *
 * ## No threshold, deliberately
 *
 * The failing case is all-or-nothing: zero probes exercised anything. It
 * is tempting to fail a run where MOST probes were unexamined, since such
 * a run is much closer to "we did not really look" than to "clean" — but
 * expressing that means picking a fraction, and no value for it is
 * defensible. 50% and 70% are equally arbitrary, and the number would sit
 * in a CI gate where changing it later breaks builds for reasons nobody
 * can reconstruct. Partial coverage is reported as a COUNT instead —
 * loudly, in the report headline and in a CLI warning — and the reader
 * draws their own line.
 */
import type { LiveProbeResult } from "./types.js";

export interface ProbeCoverage {
  total: number;
  /** Probes whose payload actually reached the field. */
  exercised: number;
  /** Probes bounced by palar's own schema-invalid arguments. */
  notTested: number;
  /** Probes whose tool could not run in this environment at all. */
  inconclusive: number;
  /** notTested + inconclusive — the two ways of learning nothing. */
  unexamined: number;
  /**
   * True when probes were attempted and not one of them exercised its
   * field. This is the "palar examined nothing" case for exit-code
   * purposes, and it is the ONLY coverage-based failure.
   */
  examinedNothing: boolean;
}

export function summarizeProbeCoverage(probes: LiveProbeResult[]): ProbeCoverage {
  const notTested = probes.filter((p) => p.status === "not-tested").length;
  const inconclusive = probes.filter((p) => p.status === "inconclusive").length;
  const unexamined = notTested + inconclusive;
  const exercised = probes.length - unexamined;
  return {
    total: probes.length,
    exercised,
    notTested,
    inconclusive,
    unexamined,
    // Guarded on length so a scan with no probes at all does not report
    // "examined nothing" here — that case is a different event (no
    // probeable field was found) and is already covered by the
    // never-reached / no-tools branches upstream.
    examinedNothing: probes.length > 0 && exercised === 0,
  };
}
