/**
 * NB: audits a server's DECLARED network posture — whether a declared egress
 * filter is switched off or unbacked by an allowlist, and whether any declared
 * exposed host points at loopback or private/link-local address space.
 *
 * Every rule here evaluates a value the manifest actually states. None fires
 * on the absence of a declaration, and that is deliberate: "absent" and
 * "disabled" are different claims, and only the second is a property of the
 * server. `network.egressFilterEnabled` is palar's own manifest key — it is
 * not part of the MCP specification, so no real-world server ships it. A rule
 * keyed on its absence reports the absence of palar metadata and fires on
 * 100% of real servers, which is zero information at high severity. It also
 * misreads the dominant case: a stdio server has no listening socket, and
 * what it may dial out to is a property of the process's runtime environment,
 * not of its manifest — which is exactly why `palar live` enforces egress
 * with iptables rather than by reading a declaration.
 */
import type { Finding, MCPServerConfig } from "../core/types.js";
import type { RuleContext, ServerRule } from "./index.js";
import type { NetworkPatterns } from "../core/config.js";
import { DEFAULT_CONFIG } from "../core/config.js";

/**
 * Internal palar category, deliberately not an OWASP MCP Top 10 ID: the
 * Top 10 has no server-side request forgery entry, so an "MCP-TOP10:" prefix
 * here would imply an alignment that does not exist.
 */
const COMPLIANCE_REFS = ["palar:SSRF"];

/**
 * Normalize a host string for pattern matching: trim, lowercase, unwrap
 * bracketed IPv6 ("[::1]:8080" → "::1"), and drop a single trailing
 * ":port" (left alone for bare IPv6, where colons are part of the address).
 */
function normalizeHost(host: string): string {
  let s = host.trim().toLowerCase();
  const bracketed = s.match(/^\[(.+)\](?::\d+)?$/);
  if (bracketed?.[1] !== undefined) return bracketed[1];
  const colons = s.split(":").length - 1;
  if (colons === 1) s = s.replace(/:\d+$/, "");
  return s;
}

function isLoopback(host: string, net: NetworkPatterns): boolean {
  return (
    net.loopbackHosts.includes(host) ||
    net.loopbackPatterns.some((p) => new RegExp(p).test(host))
  );
}

function isPrivateSubnet(host: string, net: NetworkPatterns): boolean {
  return net.privateSubnetPatterns.some((p) => new RegExp(p).test(host));
}

export const networkBoundsRule: ServerRule = {
  id: "network-bounds",
  check(server: MCPServerConfig, ctx: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const net = ctx.config?.network ?? DEFAULT_CONFIG.network;
    const basePath = `servers["${server.name}"].network`;
    const network = server.network;

    // Fires ONLY on an explicit `false` — a stated claim that egress is
    // unbounded. A missing `network` block, or a `network` block that simply
    // does not mention egressFilterEnabled, declares nothing about egress and
    // is therefore nothing to evaluate; see this module's docstring for why
    // treating that silence as a high-severity finding was wrong.
    if (network !== undefined && network.egressFilterEnabled === false) {
      findings.push({
        ruleId: "NB-001",
        pillar: "network-boundaries",
        // The config explicitly says egressFilterEnabled: false. That is
        // read, not inferred.
        confidence: "observed",
        severity: "high",
        title: `Server "${server.name}" declares egress filtering disabled`,
        detail:
          `Server "${server.name}" explicitly sets network.egressFilterEnabled ` +
          `to false, so its own configuration states that nothing bounds where ` +
          `it may make outbound connections.`,
        location: { file: ctx.file, jsonPath: `${basePath}.egressFilterEnabled` },
        remediation:
          `Set network.egressFilterEnabled to true and pair it with an ` +
          `egressAllowlist naming the destinations the server legitimately needs.`,
        complianceRefs: [...COMPLIANCE_REFS],
      });
    } else if (
      network?.egressFilterEnabled === true &&
      (!Array.isArray(network.egressAllowlist) || network.egressAllowlist.length === 0)
    ) {
      findings.push({
        ruleId: "NB-002",
        pillar: "network-boundaries",
        // Filter on, allowlist empty — both are declared facts in the file.
        confidence: "observed",
        severity: "medium",
        title: `Server "${server.name}" enables egress filtering with no allowlist`,
        detail:
          `Server "${server.name}" sets network.egressFilterEnabled to true but ` +
          `declares no egressAllowlist entries, so the filter has nothing to ` +
          `enforce against.`,
        location: { file: ctx.file, jsonPath: `${basePath}.egressAllowlist` },
        remediation:
          `Populate network.egressAllowlist with the specific hosts the server ` +
          `is expected to reach.`,
        complianceRefs: [...COMPLIANCE_REFS],
      });
    }

    const exposedHosts = Array.isArray(network?.exposedHosts)
      ? network.exposedHosts
      : [];
    exposedHosts.forEach((rawHost) => {
      if (typeof rawHost !== "string") return;
      const host = normalizeHost(rawHost);
      // Selected by VALUE, not by array position.
      //
      // This was `exposedHosts[${index}]` and that was the one path shape
      // in the codebase a reader could not rely on: reordering the array
      // moves every finding's path without changing a single host, so
      // anything that remembers a path across runs — an acknowledgement in
      // .palarrc.json above all — would silently start pointing at a
      // DIFFERENT host rather than failing to match. A key that quietly
      // matches the wrong thing is worse than one that stops matching, and
      // an index is the only construct here that fails that way.
      //
      // The raw string is used rather than the normalized one because a
      // jsonPath answers "where is this in the file", and the file
      // contains what the author wrote. Note two identical entries produce
      // two findings sharing one path: that is the same defect listed
      // twice, and one acknowledgement covering both is correct.
      //
      // input-validation.ts already avoided indices for array traversal
      // (`${path}[]`, :210); this brings the last outlier into line.
      const hostPath = `${basePath}.exposedHosts[${JSON.stringify(rawHost)}]`;
      if (isLoopback(host, net)) {
        findings.push({
          ruleId: "NB-003",
          pillar: "network-boundaries",
          // The entry IS a loopback address. What is NOT established is
          // that anything reaches it at runtime — that is a declaration
          // check, which is why this is `observed` and not `confirmed`.
          confidence: "observed",
          severity: "critical",
          title: `Server "${server.name}" exposes loopback host "${rawHost}"`,
          detail:
            `network.exposedHosts on server "${server.name}" lists ` +
            `"${rawHost}", a loopback address. Exposing loopback lets callers ` +
            `reach services on the host machine that were never meant to be ` +
            `remotely accessible.`,
          location: { file: ctx.file, jsonPath: hostPath },
          remediation:
            `Remove "${rawHost}" from exposedHosts, or replace it with the ` +
            `specific external service the server actually needs to expose.`,
          complianceRefs: [...COMPLIANCE_REFS],
        });
      } else if (isPrivateSubnet(host, net)) {
        findings.push({
          ruleId: "NB-004",
          pillar: "network-boundaries",
          // As NB-003: the declared host really is in private/link-local
          // space. No route was demonstrated.
          confidence: "observed",
          severity: "high",
          title: `Server "${server.name}" exposes private-network host "${rawHost}"`,
          detail:
            `network.exposedHosts on server "${server.name}" lists ` +
            `"${rawHost}", which sits in private or link-local address space. ` +
            `Exposing it gives callers a path onto the internal network (and, for ` +
            `169.254.x.x, potentially a cloud metadata endpoint).`,
          location: { file: ctx.file, jsonPath: hostPath },
          remediation:
            `Remove "${rawHost}" from exposedHosts or front the internal service ` +
            `with an explicitly scoped, authenticated endpoint instead.`,
          complianceRefs: [...COMPLIANCE_REFS],
        });
      }
    });

    return findings;
  },
};
