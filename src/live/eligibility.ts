/**
 * Payload eligibility: may this scan send real attack payloads to this
 * target, and — when it may not — why.
 *
 * ## The axis is loopback-vs-remote, NOT stdio-vs-sse
 *
 * The stdio/sse split that runs through liveScan.ts governs *containment*
 * (a stdio target runs inside a Docker sandbox; an SSE target has no local
 * process to wrap). That is a different question from *whether a payload
 * may be sent at all*, and conflating the two is exactly the bug this
 * module exists to end: the old probe loop had no transport branch, so an
 * SSE target — including a remote one the operator may not even own —
 * received the full injection payload set over the network, unsandboxed and
 * unconfirmable. See control.ts's docstring, which recorded that as a known
 * incoherence.
 *
 * There are three real cases, and only two of them may be probed:
 *
 *   - stdio         — always eligible. The payload runs inside the
 *                     ephemeral, network-restricted container liveScan.ts
 *                     builds, and the oracle listener shares that
 *                     container's view of the host. Contained AND
 *                     confirmable.
 *   - SSE, loopback — eligible, but NOT sandboxed. `127.0.0.0/8`, `::1`, or
 *                     `localhost` is the operator's own machine; the oracle's
 *                     loopback listener is genuinely shared with the target,
 *                     so a callback can come back. The blast radius is a real
 *                     LOCAL process with no container around it — see the
 *                     `sandboxed: false` flag, which report.ts turns into its
 *                     own warning line.
 *   - SSE, remote   — NOT eligible. Enumerate only. The oracle listener is
 *                     loopback-scoped, so a remote target's `127.0.0.1`
 *                     callback resolves to the target's OWN loopback and
 *                     never reaches palar: the probe could be neither
 *                     contained nor confirmed. Sending it anyway would be
 *                     unauthorised attack traffic to a machine palar cannot
 *                     even hear back from — all of the harm, none of the
 *                     value.
 *
 * ## Why the host is matched literally, and DNS is never resolved
 *
 * The decision is made on the literal host string in the server's `url`,
 * after stripping credentials, IPv6 brackets, and the port (all of which
 * `URL.hostname` does for us). A hostname that *resolves* to `127.0.0.1` is
 * a genuine loopback case this deliberately does NOT honour: resolving it
 * would add a DNS round trip and, worse, a TOCTOU window — the name could
 * resolve to loopback for the eligibility check and to a routable address
 * by the time the payload is sent. The literal check cannot be raced, and
 * its failure mode is the safe one (a real loopback target typed as a name
 * is enumerated rather than probed, never the reverse).
 */
import type { MCPServerConfig } from "../core/types.js";

/**
 * Loopback host literals that are not numeric. Only `localhost` — matched
 * as a literal, never resolved (see module docstring). Numeric loopback is
 * handled by isLoopbackHost's range check.
 */
const LOOPBACK_NAMES = new Set(["localhost"]);

/**
 * The bare host of a URL with credentials, brackets, and port removed, or
 * null if the string is not a parseable URL. `URL.hostname` strips
 * `user:pass@` and the `:port` suffix for us, but KEEPS the `[...]` around
 * an IPv6 literal (per the WHATWG URL spec), so those brackets are stripped
 * here — `[::1]` must reach isLoopbackHost as `::1`.
 */
export function extractHost(rawUrl: string): string | null {
  try {
    const h = new URL(rawUrl).hostname;
    if (h.length === 0) return null;
    const unbracketed = h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h;
    return unbracketed.length > 0 ? unbracketed : null;
  } catch {
    return null;
  }
}

/**
 * Whether a literal host names the local machine. Matches the whole
 * `127.0.0.0/8` range (not just the `127.0.0.1` literal — `127.0.0.53` and
 * `127.1.2.3` are loopback too), `::1`, its `::ffff:127.x.x.x` mapped form,
 * and the literal name `localhost`. No DNS resolution: a name that is not
 * `localhost` is treated as remote even if it would resolve to loopback.
 */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  if (LOOPBACK_NAMES.has(h)) return true;
  if (h === "::1") return true;
  // IPv4-mapped IPv6 (e.g. "::ffff:127.0.0.1") carries a dotted-quad tail.
  const v4 = h.startsWith("::ffff:") ? h.slice("::ffff:".length) : h;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v4);
  if (!m) return false;
  const octets = m.slice(1, 5).map((s) => Number(s));
  if (octets.some((o) => o > 255)) return false;
  return octets[0] === 127;
}

/**
 * Whether this target may be sent attack payloads, discriminated so the
 * caller can tell the two eligible cases apart (only one is sandboxed) and
 * render the ineligible case's reason verbatim.
 */
export type PayloadEligibility =
  | { eligible: true; sandboxed: true; kind: "stdio" }
  | { eligible: true; sandboxed: false; kind: "sse-loopback"; host: string }
  | { eligible: false; kind: "sse-remote"; host: string | null; notice: string };

/**
 * Classify a server for payload eligibility.
 *
 * The transport test mirrors liveScan.ts's `isStdio` (`transport !== "sse"`)
 * on purpose: the two must agree on which targets take the SSE path, so the
 * predicate is written the same way in both places. Everything that is not
 * an SSE target is stdio-eligible; an SSE target's eligibility turns
 * entirely on its host.
 */
export function classifyPayloadEligibility(server: MCPServerConfig): PayloadEligibility {
  if (server.transport !== "sse") {
    return { eligible: true, sandboxed: true, kind: "stdio" };
  }

  const host = server.url ? extractHost(server.url) : null;
  if (host !== null && isLoopbackHost(host)) {
    return { eligible: true, sandboxed: false, kind: "sse-loopback", host };
  }

  const where = host !== null ? `host "${host}"` : "an unparseable url";
  return {
    eligible: false,
    kind: "sse-remote",
    host,
    notice:
      `SSE target ${where} is not loopback — enumerated only, NO payload sent. palar's oracle ` +
      "callback listener is loopback-scoped, so a probe against a remote host could be neither " +
      "contained (there is no sandbox around a remote process) nor confirmed (its callback to " +
      "127.0.0.1 would reach its own loopback, never palar's). Point palar at a server on " +
      "127.0.0.0/8, ::1, or localhost to probe it, or use `scan --from-url` to enumerate a " +
      "remote server on purpose.",
  };
}
