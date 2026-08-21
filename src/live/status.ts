/**
 * Resolves one probe's status from the three things the scan actually
 * observed: whether an oracle callback bearing this probe's nonce arrived,
 * what the tool call itself came back as, and whether palar's own
 * arguments satisfied the schema the target advertised.
 *
 * The ordering is strict, and it is security-critical:
 *
 *   confirmed    — a callback arrived. ALWAYS wins, whatever else happened.
 *   not-tested   — no callback, the call did not succeed, and palar's own
 *                  arguments were already known to violate the target's
 *                  declared schema. The failure has a sufficient
 *                  explanation in palar's input, so nothing was learned
 *                  about the probed field.
 *   inconclusive — no callback, the call errored, palar's arguments were
 *                  schema-valid, AND a benign control call to the same
 *                  tool errored too. The tool could not run here at all,
 *                  so the payload was never the thing being answered.
 *   rejected     — no callback, palar's arguments were schema-valid, the
 *                  tool call came back as an error result
 *                  (isError === true), and either a control call came back
 *                  CLEAN or no control call was sent.
 *   unconfirmed  — no callback, and no error result.
 *
 * Why "a callback always wins" is a real rule and not a formality: a
 * SUCCESSFUL command injection whose injected command exits nonzero
 * produces BOTH isError === true AND a callback. The tool shelled out, the
 * payload ran, the oracle heard from it — and then the shell returned a
 * nonzero status, so the tool reported an error. Checking isError first
 * would label a proven, live-confirmed injection "rejected": a false
 * negative in the most dangerous direction available to this tool. The
 * callback is positive physical evidence; isError is a self-report by the
 * thing being tested. Evidence outranks self-report.
 *
 * ## Why "inconclusive" outranks "rejected", and why "not-tested" outranks it
 *
 * `inconclusive` sits above `rejected` for exactly the reason `not-tested`
 * does, below: when a failure has an explanation that is not "the target
 * refused our payload", preferring the reading that flatters the target is
 * the one move this module exists to refuse.
 *
 * It sits BELOW `not-tested` because the two are not equally good
 * explanations. `not-tested` is computed pre-flight from the target's own
 * declared schema and is exact within its scope; `inconclusive` is an
 * inference drawn from a second observation, made after the fact, on a
 * target that has by then already received a payload. When both apply, the
 * exact explanation wins. That ordering also pays for itself: a
 * `not-tested` probe never triggers a control call, because its status is
 * settled before the question arises.
 *
 * ## Why "not-tested" outranks "rejected"
 *
 * `rejected` means "the target pushed back on our payload". When palar
 * sent an argument set the target's own published schema forbids, that
 * reading is not available: the more economical explanation for the error
 * is the invalid argument, and the probed field was never reached. Ranking
 * it below `rejected` would mean preferring the explanation that flatters
 * the target.
 *
 * The concrete case is desktop-commander, which puts
 * `origin: {"enum":["ui","llm"]}` on eight tools. palar filled it with the
 * string "palar-live-probe", zod threw at the top of the handler, and
 * `start_process.command` — a field that really does reach a shell — came
 * back reading "REJECTED BY TARGET". That is a false reassurance about the
 * most dangerous tool in the sample, produced entirely by palar's own bad
 * input. probes.ts now generates schema-satisfying filler so this case
 * mostly stops arising; this status covers what filler generation cannot
 * fix (an arbitrary `pattern`, a contradictory bound).
 *
 * ## What this can and cannot distinguish — the honest limit
 *
 * The signal used here is entirely structural and entirely PRE-FLIGHT:
 * palar compares the arguments it is about to send against the schema the
 * target itself published, and knows the answer before the call leaves.
 * No error text is read, no JSON-RPC code is switched on, nothing is
 * pattern-matched. Within its scope it is exact.
 *
 * Its scope is the limit. This catches only constraints the target
 * DECLARED. A server that validates more strictly than it advertises —
 * a handler that requires an absolute path where the schema says
 * `{"type":"string"}`, a field whose real permitted set is written in the
 * description rather than in an `enum` — bounces palar's filler with
 * nothing in the schema to have predicted it, and that probe lands in
 * `rejected`, exactly as it does today.
 *
 * Recovering those would mean reading the target's error text: matching a
 * JSON-RPC -32602, or a zod issue array, or free-form prose, and hoping a
 * quoted field name in it is the argument palar got wrong rather than a
 * field the payload legitimately upset. That is guesswork presented as
 * provenance, on the exact axis this module exists to keep honest, and it
 * is also not uniform across servers: desktop-commander does not even emit
 * -32602 for this: it catches the ZodError inside the call handler and
 * returns an ordinary `isError: true` result with the issues stringified
 * into the text body. So it is deliberately not attempted, and the
 * residual under-count is stated here rather than papered over.
 *
 * What "rejected" does NOT mean:
 *
 *   It does not mean safe, and it is deliberately not "refuted". MCP's
 *   isError means only "this tool call produced an error result", which
 *   spans at least four different situations that are indistinguishable
 *   from the boolean alone:
 *
 *     1. input validation rejected the payload (the tool's own guard
 *        rails held for THIS input — not proof they hold for all inputs);
 *     2. argument/schema validation bounced the call before the tool's
 *        handler was ever dispatched (the tool's code never ran at all);
 *     3. the tool ran and refused for some unrelated reason;
 *     4. the injected command RAN and exited nonzero — evidence FOR
 *        injection, reached only when no callback arrived to prove it
 *        (e.g. the callback binary was missing, or egress was blocked).
 *
 *   `not-tested` carves out the part of (2) that palar can prove it caused
 *   itself. `inconclusive` carves out the part of (1)/(2)/(3) where the
 *   tool could not run here at all. What remains here is still not a
 *   verdict about the target's safety. It must never downgrade a finding's
 *   severity or suppress it. Callers render the tool's own response text
 *   alongside the status so a reader can tell these situations apart; this
 *   function deliberately does not try to classify them, because doing so
 *   would mean pattern-matching on free-form error strings and presenting
 *   the guess as a finding.
 *
 * ## What "inconclusive" does NOT distinguish — its own honest limit
 *
 * The control call is an outcome comparison, not a string match, and that
 * is what makes it admissible here (see control.ts). But it establishes
 * exactly one thing: the tool errored on a call that contained NO payload,
 * so the payload is not the explanation. It does not say why. At least
 * these six remain indistinguishable from `inconclusive` alone:
 *
 *   1. A dependency is missing inside the sandbox — Chromium absent for
 *      playwright-mcp, which is the case that motivated this status.
 *   2. PALAR'S OWN ISOLATION caused the failure. The sandbox denies the
 *      target network egress, mounts its directory read-only, drops
 *      capabilities and gives it no DNS resolver. A tool that needs any of
 *      those fails there and would work fine outside. On the evidence so
 *      far this is the LIKELIEST cause of an inconclusive result in
 *      practice, which means the status is often a statement about palar's
 *      environment rather than about the target. That is still more honest
 *      than `rejected`, but it is not a small caveat, and report.ts is
 *      required to say it to the reader rather than leaving it here.
 *   3. The tool is simply broken or misconfigured for every input.
 *   4. The tool refuses everything from an unrecognized caller — an auth
 *      check, an allowlist, a required session palar does not have.
 *   5. The target validates more strictly than it advertises and the
 *      BENIGN filler trips an undeclared rule too. This is the same
 *      residual documented above for `rejected`, inherited wholesale by
 *      the control call.
 *   6. The earlier payload broke the tool, and the control is collateral
 *      damage. The control is sent AFTER the probe (see liveScan.ts), so a
 *      payload that wedged the handler makes its own control error.
 *
 * And the false-negative direction, which is a real cost and not a
 * footnote: a tool that genuinely refused the payload AND is also broken
 * here reads `inconclusive`, so a true "the guard rail held for this
 * input" signal is lost. That is accepted, because this module already
 * refuses to treat `rejected` as a safety verdict — there was never much
 * signal there to lose.
 *
 * Consistent with all of the above, and enforced in escalate.ts:
 * `inconclusive` moves no severity in either direction.
 */
import type { CallbackEvent } from "./oracle.js";
import type { ProbeArgumentIssue } from "./probes.js";
import type { ControlCall, ProbeStatus, ToolCallCapture } from "./types.js";

/**
 * True when this probe's error is the kind a control call could explain —
 * i.e. the probe would otherwise resolve to `rejected`.
 *
 * Callers use this to decide whether to spend a control call at all, so
 * that the cost is one call per TOOL WITH AN ERRORED PROBE rather than one
 * per probe. Keeping the predicate here rather than in liveScan.ts means
 * the "when is a control worth sending" rule and the "what does a control
 * change" rule cannot drift apart.
 */
export function wouldBeRejected(
  callback: CallbackEvent | null,
  toolCall: ToolCallCapture | { error: string },
  argumentIssues: ProbeArgumentIssue[] = []
): boolean {
  return resolveProbeStatus(callback, toolCall, argumentIssues, null) === "rejected";
}

export function resolveProbeStatus(
  callback: CallbackEvent | null,
  toolCall: ToolCallCapture | { error: string },
  argumentIssues: ProbeArgumentIssue[] = [],
  control: ControlCall | null = null
): ProbeStatus {
  // Order matters — see the module docstring. Callback first, always.
  // A callback proves the payload was interpreted, which settles the
  // question regardless of how invalid the rest of the argument set was.
  if (callback) return "confirmed";

  const transportFailed = "error" in toolCall;
  const erroredResult = !transportFailed && toolCall.isError === true;

  // Only claimed for a call that did NOT succeed. A schema-invalid
  // argument set the target accepted anyway (it did not enforce its own
  // declaration) exercised the field for real, and the result stands.
  //
  // Above the control check on purpose: this explanation is exact and
  // pre-flight, the control's is inferred and after the fact. See the
  // docstring.
  if (argumentIssues.length > 0 && (transportFailed || erroredResult)) return "not-tested";

  // A transport/protocol failure ({ error }) is NOT a rejection: the call
  // never completed, so we do not know whether the handler ran. That stays
  // unconfirmed rather than claiming the target pushed back.
  if (erroredResult) {
    // A control that ERRORED means the tool does not run here at all, so
    // the payload was never the thing being answered. A control that
    // SUCCEEDED earns the rejection: the tool demonstrably runs, and it
    // chose to error on the payload specifically. No control at all leaves
    // the probe exactly where it was before this instrument existed —
    // `rejected`, with the ambiguity intact and rendered as such.
    if (control?.attempted === true && control.outcome === "errored") return "inconclusive";
    return "rejected";
  }

  return "unconfirmed";
}
