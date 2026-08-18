/**
 * Resolves one probe's status from the two things the scan actually
 * observed: whether an oracle callback bearing this probe's nonce arrived,
 * and what the tool call itself came back as.
 *
 * The ordering is strict, and it is security-critical:
 *
 *   confirmed   — a callback arrived. ALWAYS wins, whatever the tool call
 *                 returned.
 *   rejected    — no callback, and the tool call came back as an error
 *                 result (isError === true).
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
 *   Because (4) lives in this bucket, "rejected" must never downgrade a
 *   finding's severity or suppress it. It is a provenance label recording
 *   what was observed, not a verdict about the target's safety. Callers
 *   render the tool's own response text alongside the status so a reader
 *   can tell these situations apart; this function deliberately does not
 *   try to classify them, because doing so would mean pattern-matching on
 *   free-form error strings and presenting the guess as a finding.
 */
import type { CallbackEvent } from "./oracle.js";
import type { ProbeStatus, ToolCallCapture } from "./types.js";

export function resolveProbeStatus(
  callback: CallbackEvent | null,
  toolCall: ToolCallCapture | { error: string }
): ProbeStatus {
  // Order matters — see the module docstring. Callback first, always.
  if (callback) return "confirmed";

  // A transport/protocol failure ({ error }) is NOT a rejection: the call
  // never completed, so we do not know whether the handler ran. That stays
  // unconfirmed rather than claiming the target pushed back.
  if (!("error" in toolCall) && toolCall.isError === true) return "rejected";

  return "unconfirmed";
}
