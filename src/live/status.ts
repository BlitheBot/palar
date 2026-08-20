/**
 * Resolves one probe's status from the three things the scan actually
 * observed: whether an oracle callback bearing this probe's nonce arrived,
 * what the tool call itself came back as, and whether palar's own
 * arguments satisfied the schema the target advertised.
 *
 * The ordering is strict, and it is security-critical:
 *
 *   confirmed   — a callback arrived. ALWAYS wins, whatever else happened.
 *   not-tested  — no callback, the call did not succeed, and palar's own
 *                 arguments were already known to violate the target's
 *                 declared schema. The failure has a sufficient
 *                 explanation in palar's input, so nothing was learned
 *                 about the probed field.
 *   rejected    — no callback, palar's arguments were schema-valid, and
 *                 the tool call came back as an error result
 *                 (isError === true).
 *   unconfirmed — no callback, and no error result.
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
 *   itself. The rest of (2) — a bounce on a rule the schema never stated —
 *   stays here, so this bucket is narrower than it was but is still not a
 *   verdict about the target's safety. It must never downgrade a finding's
 *   severity or suppress it. Callers render the tool's own response text
 *   alongside the status so a reader can tell these situations apart; this
 *   function deliberately does not try to classify them, because doing so
 *   would mean pattern-matching on free-form error strings and presenting
 *   the guess as a finding.
 */
import type { CallbackEvent } from "./oracle.js";
import type { ProbeArgumentIssue } from "./probes.js";
import type { ProbeStatus, ToolCallCapture } from "./types.js";

export function resolveProbeStatus(
  callback: CallbackEvent | null,
  toolCall: ToolCallCapture | { error: string },
  argumentIssues: ProbeArgumentIssue[] = []
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
  if (argumentIssues.length > 0 && (transportFailed || erroredResult)) return "not-tested";

  // A transport/protocol failure ({ error }) is NOT a rejection: the call
  // never completed, so we do not know whether the handler ran. That stays
  // unconfirmed rather than claiming the target pushed back.
  if (erroredResult) return "rejected";

  return "unconfirmed";
}
