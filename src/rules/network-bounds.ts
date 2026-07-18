/**
 * NB: audits a server's declared network posture — whether egress filtering
 * is explicitly enabled and backed by an allowlist, and whether any exposed
 * host points at loopback or private/link-local address space.
 */
import type { Finding, MCPServerConfig } from "../core/types.js";
import type { RuleContext, ServerRule } from "./index.js";
import type { NetworkPatterns } from "../core/config.js";
import { DEFAULT_CONFIG } from "../core/config.js";

const COMPLIANCE_REFS = ["MCP-TOP10:C3-SSRF"];

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

    if (network?.egressFilterEnabled !== true) {
      findings.push({
        ruleId: "NB-001",
        pillar: "network-boundaries",
        severity: "high",
        title: `Server "${server.name}" declares no egress filter`,
        detail:
          `Server "${server.name}" does not set network.egressFilterEnabled to ` +
          `true, so nothing in its configuration bounds where it may make ` +
          `outbound connections.`,
        location: { file: ctx.file, jsonPath: `${basePath}.egressFilterEnabled` },
        remediation:
          `Set network.egressFilterEnabled to true and pair it with an ` +
          `egressAllowlist naming the destinations the server legitimately needs.`,
        complianceRefs: [...COMPLIANCE_REFS],
      });
    } else if (
      !Array.isArray(network.egressAllowlist) ||
      network.egressAllowlist.length === 0
    ) {
      findings.push({
        ruleId: "NB-002",
        pillar: "network-boundaries",
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
    exposedHosts.forEach((rawHost, index) => {
      if (typeof rawHost !== "string") return;
      const host = normalizeHost(rawHost);
      const hostPath = `${basePath}.exposedHosts[${index}]`;
      if (isLoopback(host, net)) {
        findings.push({
          ruleId: "NB-003",
          pillar: "network-boundaries",
          severity: "critical",
          title: `Server "${server.name}" exposes loopback host "${rawHost}"`,
          detail:
            `Entry ${index} of network.exposedHosts on server "${server.name}" ` +
            `is "${rawHost}", a loopback address. Exposing loopback lets callers ` +
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
          severity: "high",
          title: `Server "${server.name}" exposes private-network host "${rawHost}"`,
          detail:
            `Entry ${index} of network.exposedHosts on server "${server.name}" ` +
            `is "${rawHost}", which sits in private or link-local address space. ` +
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
