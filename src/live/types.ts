/**
 * Shared types for the live scan pass. Deliberately separate from
 * core/types.ts's Finding/AuditResult — the static analyzer's output
 * contract is left untouched by this work (see report.ts for how the two
 * are cross-referenced for display without merging their types).
 */
import type { CallbackEvent } from "./oracle.js";
import type { ProbeKind } from "./probes.js";

/**
 * Outcome of a single probe. See status.ts for the strict resolution
 * order and, in particular, for why "rejected" is not a claim that the
 * target is safe (it spans four different situations, one of which is a
 * successful injection) and must never downgrade or suppress a finding.
 */
export type ProbeStatus = "confirmed" | "rejected" | "unconfirmed";

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

export interface LiveAuditResult {
  timestamp: string;
  serverName: string;
  transportKind: "stdio" | "sse";
  pid: number | null;
  connectDurationMs: number;
  liveTools: { name: string; description?: string }[];
  toolDrift: ToolDriftEntry[];
  probes: LiveProbeResult[];
  poisoningChecks: PoisoningLiveCheck[];
  oracle: { baseUrl: string };
  warnings: string[];
  errors: string[];
  durationMs: number;
}
