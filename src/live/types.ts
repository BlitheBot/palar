/**
 * Shared types for the live scan pass. Deliberately separate from
 * core/types.ts's Finding/AuditResult — the static analyzer's output
 * contract is left untouched by this work (see report.ts for how the two
 * are cross-referenced for display without merging their types).
 */
import type { MCPToolAnnotations } from "../core/types.js";
import type { CallbackEvent } from "./oracle.js";
import type { ProbeArgumentIssue, ProbeKind } from "./probes.js";
import type { PayloadEligibility } from "./eligibility.js";

/**
 * Outcome of a single probe. See status.ts for the strict resolution
 * order and, in particular, for why "rejected" is not a claim that the
 * target is safe (it spans four different situations, one of which is a
 * successful injection) and must never downgrade or suppress a finding.
 *
 * Two of these are not about the target at all, and both exist to stop a
 * failure palar caused from reading as a failure the target chose:
 *
 *   "not-tested"   — the call failed with palar's own arguments already
 *                    known to violate the target's declared schema, so the
 *                    probed field was never exercised.
 *   "inconclusive" — a benign control call to the same tool errored too,
 *                    so the tool could not run here at all and the payload
 *                    was never the thing being answered. See control.ts.
 */
export type ProbeStatus =
  | "confirmed"
  | "not-tested"
  | "inconclusive"
  | "rejected"
  | "unconfirmed";

/**
 * What happened when palar sent this tool a benign, payload-free control
 * call — or why it declined to.
 *
 * Deliberately a separate field rather than another ProbeStatus value.
 * "no control was attempted" is not a third outcome of the probe, it is a
 * missing piece of evidence ABOUT the probe, and folding it into the
 * status would make an ungated tool indistinguishable from one that passed
 * a control. That distinction is the whole point of the two-tier rendering
 * in report.ts: a reader who knows palar runs controls must not read every
 * "rejected" as controlled.
 */
export type ControlCall =
  | {
      attempted: false;
      /** Why the gate withheld it — rendered verbatim. See control.ts. */
      reason: string;
    }
  | {
      attempted: true;
      /**
       * "succeeded" — the benign call came back without an error result,
       * so the tool DOES run here and the probe's error is the target
       * answering the payload. This is what earns a `rejected`.
       * "errored" — the benign call errored, timed out, or failed in
       * transport. The tool did not run here for reasons that have nothing
       * to do with the payload, and the probe resolves `inconclusive`.
       */
      outcome: "succeeded" | "errored";
      args: Record<string, unknown>;
      toolCall: ToolCallCapture | { error: string };
      durationMs: number;
    };

export interface ToolCallCapture {
  isError?: boolean;
  /** Joined text content from the tool result, truncated to 500 chars. */
  textPreview: string;
}

export interface LiveProbeResult {
  toolName: string;
  fieldPath: string;
  kind: ProbeKind;
  reason: string;
  payload: string;
  nonce: string;
  /**
   * Constraints the target's own declared schema places on this call's
   * arguments that palar could not satisfy — computed before the call was
   * sent, from the schema alone. Empty for a probe whose arguments were
   * schema-valid, which is the normal case.
   */
  argumentIssues: ProbeArgumentIssue[];
  status: ProbeStatus;
  callback: CallbackEvent | null;
  callbackTimeoutMs: number;
  toolCall: ToolCallCapture | { error: string };
  /**
   * The benign control call for this probe's tool, or why none was sent.
   * Null when the question never arose — a probe that confirmed, was
   * not-tested, or went unconfirmed has no error needing an explanation,
   * and control.ts is never consulted for it.
   *
   * Shared across every probe on the same tool: one control result answers
   * "does this tool run here at all" for all of them, so it is resolved
   * once per tool per scan and copied.
   */
  control: ControlCall | null;
}

export interface PoisoningLiveCheck {
  toolName: string;
  /** Zero-width/invisible code points found in the LIVE description. */
  codePoints: number[];
  /** null when there's no static definition of this tool to compare against. */
  liveDescriptionMatchesStatic: boolean | null;
  toolCall: ToolCallCapture | { error: string } | null;
  /**
   * Why no direct call was made, when the control gate withheld it.
   * Null when the call went ahead.
   *
   * This check has always sent a benign call to any tool with a poisoned
   * description, and it did so with no gate at all — it predates the gate.
   * It is now gated by the same rule as the control call, because a
   * side-effect gate with a second, older path around it is not a gate.
   */
  withheldReason: string | null;
}

export interface ToolDriftEntry {
  toolName: string;
  /** A tool declared in the static JSON but never returned by the live server's listTools() (or vice versa) — something purely static analysis cannot see. */
  kind: "only-in-static-file" | "only-in-live-server";
}

/**
 * What one live scan of one server actually achieved, before any question
 * about what it found.
 *
 * The same distinction enumerate.ts's EnumerationResult draws, for the same
 * reason and with deliberately the same words — a `live` run that never got
 * a tool list is the identical event as a `scan --from-command` that never
 * got one, and the two commands must not describe it differently:
 *
 *   - `probed`        — the target answered the handshake and listed at
 *     least one tool. Whatever the probes then said, palar examined
 *     something and a verdict is meaningful.
 *   - `no-tools`      — the handshake succeeded and the server truthfully
 *     reported nothing. No tool was exercised because there was none to
 *     exercise.
 *   - `never-reached` — palar never got a tool list at all: the declared
 *     command names no program on this disk, the container never started,
 *     the handshake timed out, the SSE endpoint refused. This says nothing
 *     whatsoever about the target's security posture, and it must never be
 *     reported in a shape a clean pass could also produce.
 *
 * This lives on the result rather than being inferred from `errors.length`
 * because the two are not the same question: a run can reach a target,
 * probe it, and still collect an error on the way out.
 */
export type LiveOutcome = "probed" | "no-tools" | "never-reached";

export interface LiveAuditResult {
  timestamp: string;
  serverName: string;
  transportKind: "stdio" | "sse";
  /**
   * Whether this scan was allowed to send attack payloads, and — when it
   * was not — why, in a sentence for the reader. The axis is
   * loopback-vs-remote, not stdio-vs-sse: a stdio target and a loopback SSE
   * target are both probed (the first inside a container, the second
   * against a real local process with none), while an SSE target on any
   * other host is enumerated only. See eligibility.ts. Carried on the
   * result so `--json`, the report, and the exit path all read one decision
   * rather than re-deriving it.
   */
  payloadEligibility: PayloadEligibility;
  outcome: LiveOutcome;
  /**
   * Why the target was never reached, in one sentence a reader can act on.
   * Non-null exactly when `outcome` is `"never-reached"` — carried
   * separately from `errors` so a consumer never has to pick the
   * load-bearing string out of a list.
   */
  unreachable: { reason: string } | null;
  pid: number | null;
  /**
   * How long palar spent preparing its OWN tools before the target was
   * touched: Docker preflight, building the sandbox images if they were
   * missing, creating the network, starting the oracle, installing the
   * firewall. Reported separately because it is not the target's latency
   * and must never be read as such — on a first run, building the runtime
   * image dominates this number and nothing has been asked of the server
   * yet.
   */
  sandboxSetupMs: number;
  /**
   * How long `docker run` took to get this scan's container into a running
   * state, stdio only. Also palar's own latency, also not the target's.
   */
  containerStartMs: number;
  /**
   * How long the TARGET took to answer the MCP handshake, measured from the
   * moment its container was running. This is the only one of the three
   * that says anything about the server, and it is what
   * `--connect-timeout-ms` bounds.
   */
  connectDurationMs: number;
  /**
   * What the server's own listTools() returned, including the claims it
   * makes about each tool. The annotations are kept because a probe
   * result is only half of a contradiction — the other half is what the
   * tool declared about itself, and dropping it here would mean
   * re-connecting to the target to ask again.
   */
  liveTools: {
    name: string;
    title?: string;
    description?: string;
    annotations?: MCPToolAnnotations;
  }[];
  toolDrift: ToolDriftEntry[];
  probes: LiveProbeResult[];
  poisoningChecks: PoisoningLiveCheck[];
  oracle: { baseUrl: string };
  warnings: string[];
  errors: string[];
  durationMs: number;
}
