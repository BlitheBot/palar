/**
 * Shared types for the live scan pass. Deliberately separate from
 * core/types.ts's Finding/AuditResult — the static analyzer's output
 * contract is left untouched by this work (see report.ts for how the two
 * are cross-referenced for display without merging their types).
 */
import type { MCPToolAnnotations } from "../core/types.js";
import type { CallbackEvent } from "./oracle.js";
import type { ProbeArgumentIssue, ProbeKind } from "./probes.js";

/**
 * Outcome of a single probe. See status.ts for the strict resolution
 * order and, in particular, for why "rejected" is not a claim that the
 * target is safe (it spans four different situations, one of which is a
 * successful injection) and must never downgrade or suppress a finding.
 *
 * "not-tested" is the one status that is not about the target at all: it
 * records that the call failed with palar's own arguments already known to
 * violate the target's declared schema, so the probed field was never
 * exercised and nothing was learned about it either way.
 */
export type ProbeStatus = "confirmed" | "not-tested" | "rejected" | "unconfirmed";

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
}

export interface PoisoningLiveCheck {
  toolName: string;
  /** Zero-width/invisible code points found in the LIVE description. */
  codePoints: number[];
  /** null when there's no static definition of this tool to compare against. */
  liveDescriptionMatchesStatic: boolean | null;
  toolCall: ToolCallCapture | { error: string } | null;
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
