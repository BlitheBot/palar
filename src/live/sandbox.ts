/**
 * Docker-based isolation for `mcpguard live`'s stdio targets. This is what
 * makes connector.ts's spawn a contained one: the target's declared
 * command/args run inside an ephemeral, network-restricted container
 * instead of directly on this host. See README.md's "Live scanning"
 * section for what this does and doesn't cover.
 *
 * Host-reachability for the oracle differs by Docker backend, so this
 * module detects which one it's on at runtime (isDockerDesktop() below)
 * rather than assuming one:
 *
 *   - Docker Desktop (Windows/WSL2): the daemon and all container
 *     networking run inside a separate VM that this process is not part of.
 *     The bridge gateway IP Docker reports is only a real, bindable address
 *     *inside* that VM — this host process gets EADDRNOTAVAIL trying to
 *     bind to it, no matter how correctly that IP was queried. Instead, the
 *     oracle binds to ordinary host loopback, and Docker Desktop's own
 *     host.docker.internal (already wired up out of the box, including for
 *     custom bridge networks) forwards container traffic to it via an
 *     internal host-proxy IP — resolved fresh per scan
 *     (resolveDockerDesktopHostProxyIp below) since it isn't documented as
 *     a stable, hardcodable address.
 *   - Native Linux Engine: host and containers share one network
 *     namespace, so a listener bound to 127.0.0.1 is NOT reachable from a
 *     container even via `--add-host=host.docker.internal:host-gateway`
 *     (a loopback-bound socket only accepts loopback-origin connections),
 *     but binding directly to the scan's own bridge network's gateway
 *     address works. `--add-host=host.docker.internal:host-gateway` itself
 *     resolves to the *default* `docker0` bridge's gateway here, not
 *     whatever custom bridge network the container is actually attached
 *     to, so dockerRunArgs() below pins host.docker.internal to a literal
 *     address of its own rather than relying on that magic value.
 *
 * Verification status, stated honestly because it's the whole basis for
 * trusting the containment claims: **Docker Desktop (Windows/WSL2) is the
 * backend actually exercised end-to-end here.** The egress firewall was
 * verified empirically on it by dumping live netfilter state mid-scan and
 * probing from a second shell — confirming that a host-namespace listener
 * is unreachable from the sandbox, that DNS resolution fails, and that the
 * oracle callback still lands. The native Linux Engine path is implemented
 * from documented Docker/netfilter behavior and is *not* verified
 * end-to-end here; nftables-only hosts (where the `iptables` shim may not
 * apply these rules as written) are likewise untested. Treat the Linux
 * Engine path as reasoned-but-unproven, and re-run the same checks there
 * before relying on it.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { MCPServerConfig } from "../core/types.js";
import { buildCleanEnv } from "./env.js";

const execFileAsync = promisify(execFile);

const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const TARGET_RUNTIME_DIR = join(REPO_ROOT, "docker", "target-runtime");
const NET_HELPER_DIR = join(REPO_ROOT, "docker", "net-helper");
const TARGET_RUNTIME_IMAGE = "mcpguard-target-runtime:local";
const NET_HELPER_IMAGE = "mcpguard-net-helper:local";

/**
 * The container's only nameserver: its own loopback, where nothing listens.
 * Nothing about scanning an MCP server requires resolving arbitrary
 * hostnames, so the sandbox gets no working resolver at all rather than
 * inheriting the daemon's forwarding one (which, verified empirically,
 * keeps answering external queries even with the egress chains below in
 * place — Docker's embedded resolver forwards on the container's behalf
 * through plumbing that never appears as container-sourced packets in
 * either DOCKER-USER or INPUT).
 *
 * 127.0.0.1 rather than a reserved/unroutable address on purpose: the
 * query never leaves the container's own netns, so resolution fails
 * instantly with ECONNREFUSED instead of burning ~10s of resolver
 * timeouts per lookup (measured both ways). A target could of course bind
 * its own resolver there and answer itself, which gains it nothing — every
 * address it could resolve to is still REJECTed by the egress chain.
 *
 * The oracle callback is unaffected: dockerRunArgs() pins
 * host.docker.internal via --add-host (i.e. /etc/hosts), which needs no
 * resolver at all.
 */
const BLACKHOLE_DNS = "127.0.0.1";

export class SandboxError extends Error {}

async function docker(args: string[]): Promise<string> {
  try {
    const { stdout } = await execFileAsync("docker", args);
    return stdout;
  } catch (err) {
    const stderr = (err as { stderr?: string }).stderr;
    throw new SandboxError(
      `docker ${args[0]} failed: ${(stderr && stderr.trim()) || (err as Error).message}`
    );
  }
}

/** Ignores failure entirely — used only in teardown, which must be best-effort. */
async function dockerBestEffort(args: string[]): Promise<void> {
  try {
    await execFileAsync("docker", args);
  } catch {
    // Teardown is defensive by design: a missing container/network/rule is
    // the expected outcome of a previous successful cleanup, not an error.
  }
}

async function ensureImageBuilt(image: string, contextDir: string): Promise<void> {
  try {
    await execFileAsync("docker", ["image", "inspect", image]);
    return;
  } catch {
    // Not present locally — fall through to build.
  }
  await docker(["build", "-t", image, contextDir]);
}

/**
 * Preflights Docker itself: fails closed with an actionable error rather
 * than letting `live` silently fall back to unsandboxed execution.
 */
async function preflightDocker(): Promise<void> {
  try {
    await execFileAsync("docker", ["version", "--format", "{{.Server.Version}}"]);
  } catch (err) {
    throw new SandboxError(
      "mcpguard live requires Docker to sandbox stdio targets, but `docker version` failed " +
        `(${(err as Error).message}). Install Docker and make sure the daemon is running — ` +
        "there is no unsandboxed fallback."
    );
  }
}

interface NetworkInfo {
  subnet: string;
  gatewayIp: string;
}

async function inspectNetwork(name: string): Promise<NetworkInfo> {
  const raw = await docker(["network", "inspect", name, "--format", "{{json .IPAM.Config}}"]);
  const config = JSON.parse(raw) as { Subnet?: string; Gateway?: string }[];
  const entry = config[0];
  if (!entry?.Subnet || !entry.Gateway) {
    throw new SandboxError(`docker network ${name}: no IPAM subnet/gateway assigned`);
  }
  return { subnet: entry.Subnet, gatewayIp: entry.Gateway };
}

/**
 * Docker Desktop (Mac/Windows) runs the daemon and every container network
 * inside a separate VM; this process runs on the real host OS outside that
 * VM. A bridge network's gateway IP exists only inside the VM's netns, so
 * the host can `docker network inspect` it but can never bind a listener to
 * it — confirmed empirically: `net.createServer().listen(0, gatewayIp)`
 * fails with EADDRNOTAVAIL even though the address is real and correct
 * from Docker's own point of view. Native Linux Engine has no such split —
 * host and containers share one network stack, so binding to the bridge
 * gateway from the host is expected to work (per documented behavior; not
 * verified end-to-end here — see this module's header for exactly which
 * backend the containment claims were measured on). `docker info`'s OperatingSystem
 * field reads "Docker Desktop" only in the VM case; a real Linux host
 * reports its actual distro name there instead.
 */
async function isDockerDesktop(): Promise<boolean> {
  const raw = await docker(["info", "--format", "{{.OperatingSystem}}"]);
  return raw.trim() === "Docker Desktop";
}

/**
 * The address containers on `networkName` actually land on when they reach
 * for the host — what egress-firewall ACCEPT rules must allow. On native
 * Linux Engine that's the bridge's own gateway IP (the host sits directly
 * on that network). On Docker Desktop, `host.docker.internal` already
 * resolves out of the box — for custom bridge networks too, not just the
 * default one — to an internal VPNKit/WSL host-proxy IP that forwards to
 * the real host; that proxy IP, not the (unreachable-from-the-host) bridge
 * gateway, is where the traffic actually goes. Resolved fresh per scan
 * network rather than hardcoded/cached, since the proxy address isn't
 * documented as stable across Docker Desktop versions or backends
 * (Hyper-V vs WSL2 vs macOS).
 */
async function resolveDockerDesktopHostProxyIp(networkName: string): Promise<string> {
  const out = await docker([
    "run",
    "--rm",
    "--network",
    networkName,
    NET_HELPER_IMAGE,
    "getent",
    "hosts",
    "host.docker.internal",
  ]);
  const ip = out.trim().split(/\s+/)[0];
  if (!ip) {
    throw new SandboxError(
      "could not resolve host.docker.internal from inside the scan network " +
        "(Docker Desktop is expected to provide this automatically)"
    );
  }
  return ip;
}

export class TargetSandbox {
  readonly id: string;
  readonly networkName: string;
  readonly containerName: string;
  readonly chainName: string;
  readonly gatewayIp: string;
  readonly subnet: string;
  readonly isDockerDesktop: boolean;
  /**
   * Where containers on this network land when they reach the host —
   * gatewayIp on native Linux Engine, Docker Desktop's resolved host-proxy
   * IP on Docker Desktop. Egress firewall ACCEPT rules must target this,
   * not always gatewayIp (see resolveDockerDesktopHostProxyIp above).
   */
  readonly hostReachableIp: string;
  /**
   * Where the oracle listener itself must bind on this machine to actually
   * succeed. gatewayIp on native Linux Engine (host and containers share
   * one netns). Plain loopback on Docker Desktop, since the gateway IP
   * lives only inside the Desktop VM and is never bindable from this host
   * process (see isDockerDesktop above).
   */
  readonly oracleBindHost: string;

  private firewallInstalled = false;
  private torn = false;

  private constructor(
    id: string,
    networkName: string,
    net: NetworkInfo,
    isDockerDesktop: boolean,
    hostReachableIp: string
  ) {
    this.id = id;
    this.networkName = networkName;
    this.containerName = `mcpg-${id}`;
    this.chainName = `MCPG-${id}`;
    this.gatewayIp = net.gatewayIp;
    this.subnet = net.subnet;
    this.isDockerDesktop = isDockerDesktop;
    this.hostReachableIp = hostReachableIp;
    this.oracleBindHost = isDockerDesktop ? "127.0.0.1" : net.gatewayIp;
  }

  /** Preflights Docker, builds both images if missing, and creates a fresh per-scan bridge network. */
  static async create(): Promise<TargetSandbox> {
    await preflightDocker();
    await ensureImageBuilt(TARGET_RUNTIME_IMAGE, TARGET_RUNTIME_DIR);
    await ensureImageBuilt(NET_HELPER_IMAGE, NET_HELPER_DIR);

    const id = randomBytes(4).toString("hex");
    const networkName = `mcpg-net-${id}`;
    await docker(["network", "create", "--driver", "bridge", networkName]);
    const net = await inspectNetwork(networkName);
    const desktop = await isDockerDesktop();
    const hostReachableIp = desktop
      ? await resolveDockerDesktopHostProxyIp(networkName)
      : net.gatewayIp;
    return new TargetSandbox(id, networkName, net, desktop, hostReachableIp);
  }

  /**
   * Installs egress control: a per-scan MCPG-<id> chain (ACCEPT to the
   * oracle's port on whatever address containers reach the host through,
   * REJECT everything else) plus jump rules into two shared chains.
   * Keeping the ACCEPT/REJECT pair in a scan-owned chain, rather than
   * inline in those chains, limits concurrent-scan interference to the
   * jump-rule insert/delete — still shared, host-global mutable state, but
   * a much smaller footprint than editing them directly.
   *
   * Both jumps are required, because they cover disjoint traffic:
   *   - DOCKER-USER is only consulted for *forwarded* traffic (packets
   *     routed through the host on their way somewhere else). It covers
   *     the container reaching the outside world, another container, or —
   *     on Docker Desktop — the real host via the host-proxy address.
   *   - INPUT is what host-*destined* traffic hits: packets that terminate
   *     on the host's own network stack rather than being forwarded,
   *     which is every connection to the bridge gateway address itself.
   *     DOCKER-USER never sees these. Without this jump the sandbox could
   *     still reach services listening on the host — verified empirically
   *     on Docker Desktop: a listener in the daemon's netns was reachable
   *     from the sandbox at the gateway address with only the DOCKER-USER
   *     jump installed, and refused once this INPUT jump was added.
   *
   * The INPUT jump is scoped `-s <subnet>` to this scan's own bridge
   * network, so it can only ever match traffic originating from this
   * sandbox — it does not filter anything else arriving at the host.
   */
  async installFirewall(oraclePort: number): Promise<void> {
    // Set before the script runs, not after it succeeds: if a later step in
    // the chain (e.g. the DOCKER-USER jump) fails after an earlier one
    // (e.g. `iptables -N`) already created state, teardown() still needs to
    // know there's something to clean up. teardown()'s own cleanup script
    // is independently best-effort per step, so attempting it against
    // partially-created state is always safe.
    this.firewallInstalled = true;
    const script = [
      `iptables -N ${this.chainName}`,
      `iptables -A ${this.chainName} -d ${this.hostReachableIp} -p tcp --dport ${oraclePort} -j ACCEPT`,
      `iptables -A ${this.chainName} -j REJECT`,
      `iptables -I DOCKER-USER -s ${this.subnet} -j ${this.chainName}`,
      `iptables -I INPUT -s ${this.subnet} -j ${this.chainName}`,
    ].join(" && ");
    await docker([
      "run",
      "--rm",
      "--network",
      "host",
      "--cap-add=NET_ADMIN",
      "--cap-add=NET_RAW",
      NET_HELPER_IMAGE,
      "sh",
      "-c",
      script,
    ]);
  }

  /**
   * Full `docker run` argv for the target's stdio process. `-i` is
   * required — without it stdin isn't kept open and StdioClientTransport's
   * pipe-based protocol breaks (a plain `docker run` with no -i/-t closes
   * stdin immediately).
   */
  dockerRunArgs(server: MCPServerConfig, targetDir: string): string[] {
    if (!server.command) {
      throw new SandboxError(`server "${server.name}" declares no "command" to run in the sandbox`);
    }

    const args = [
      "run",
      "-i",
      "--rm",
      "--name",
      this.containerName,
      "--network",
      this.networkName,
      // Pin host.docker.internal to a literal address on both backends,
      // rather than leaving it to name resolution. hostReachableIp is
      // already the correct answer for each (the bridge gateway on native
      // Linux Engine, where Docker's own "host-gateway" magic value would
      // wrongly resolve to the *default* docker0 bridge; the resolved
      // host-proxy IP on Docker Desktop, which is what Desktop's built-in
      // resolution would have returned anyway). Doing it via /etc/hosts is
      // what lets the sandbox run with no working resolver at all — see
      // BLACKHOLE_DNS.
      "--add-host",
      `host.docker.internal:${this.hostReachableIp}`,
      // No DNS. See BLACKHOLE_DNS: nothing in scanning an MCP server needs
      // to resolve arbitrary hostnames, and the daemon's forwarding
      // resolver otherwise answers external queries straight through the
      // egress firewall.
      "--dns",
      BLACKHOLE_DNS,
      "-v",
      `${targetDir}:/target:ro`,
      "-w",
      "/target",
    ];

    const env = buildCleanEnv(server.env);
    for (const [key, value] of Object.entries(env)) {
      args.push("-e", `${key}=${value}`);
    }

    args.push(
      "--cap-drop=ALL",
      "--security-opt=no-new-privileges",
      "--pids-limit=256",
      "--memory=512m",
      "--cpus=1",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,noexec,nosuid,size=64m",
      TARGET_RUNTIME_IMAGE,
      server.command,
      ...(server.args ?? [])
    );

    return args;
  }

  /**
   * Idempotent: safe to call more than once (liveScan.ts calls it from
   * connector.ts's close() and again, defensively, from its own finally
   * block in case connectLive() itself threw before a connection existed).
   * `docker rm -f` is a deliberate backstop — killing the local `docker
   * run` CLI client by pid does not stop the container itself.
   */
  async teardown(): Promise<void> {
    if (this.torn) return;
    this.torn = true;

    await dockerBestEffort(["rm", "-f", this.containerName]);

    if (this.firewallInstalled) {
      // Each step separated by `;`, not `&&`, and individually allowed to
      // fail: installFirewall() may have died partway through (e.g. the
      // chain got created but one of the two jumps never landed), and an
      // early failure here (e.g. "no such rule" deleting a jump that was
      // never inserted) must not skip flushing/deleting the chain itself.
      const script = [
        `iptables -D INPUT -s ${this.subnet} -j ${this.chainName} || true`,
        `iptables -D DOCKER-USER -s ${this.subnet} -j ${this.chainName} || true`,
        `iptables -F ${this.chainName} || true`,
        `iptables -X ${this.chainName} || true`,
      ].join("; ");
      await dockerBestEffort([
        "run",
        "--rm",
        "--network",
        "host",
        "--cap-add=NET_ADMIN",
        "--cap-add=NET_RAW",
        NET_HELPER_IMAGE,
        "sh",
        "-c",
        script,
      ]);
    }

    await dockerBestEffort(["network", "rm", this.networkName]);
  }
}

/** What a startup sweep reclaimed, for reporting. Empty means nothing was left behind. */
export interface SweepResult {
  containers: string[];
  networks: string[];
  /** One line per netfilter object removed (jump rules and chains). */
  iptables: string[];
}

/**
 * Reclaims sandbox state left behind by a previous run that never reached
 * teardown() — a crash, a `kill`, or a Ctrl-C that killed this process
 * before its `finally` block ran. That leftover state is not inert: a
 * `docker run` client killed by Ctrl-C does NOT stop the container it
 * started (which is exactly why teardown() uses `docker rm -f` rather than
 * killing a pid), so an orphaned run can leave a live target container
 * attached to a live network, plus MCPG-* chains and their DOCKER-USER /
 * INPUT jumps wired into host-global netfilter state indefinitely.
 *
 * Best-effort throughout, and never throws: a failure to reclaim is
 * reported as "nothing reclaimed", never as a scan-blocking error. Call it
 * once at startup, before any sandbox is created, so it can't race the
 * caller's own state.
 *
 * Concurrency caveat, deliberately not papered over: this treats every
 * `mcpg-`/`MCPG-` object as orphaned, because it cannot distinguish a crashed
 * run's leftovers from a concurrent run's live state — a container left
 * running by Ctrl-C looks exactly like one a healthy concurrent scan is
 * using. Since a running orphan is the single most important thing to
 * reclaim, the sweep takes it. Concurrent `mcpguard live` invocations
 * against one Docker daemon were already unsupported (see README's named
 * gaps); this makes that sharper rather than adding a new limitation.
 */
export async function sweepOrphanedSandboxState(): Promise<SweepResult> {
  const result: SweepResult = { containers: [], networks: [], iptables: [] };

  // Docker missing entirely is not an error here: an SSE-only run needs no
  // Docker at all, and a stdio run fails closed later with an actionable
  // message from preflightDocker(). Either way there is nothing to sweep.
  try {
    await execFileAsync("docker", ["version", "--format", "{{.Server.Version}}"]);
  } catch {
    return result;
  }

  const lines = (out: string): string[] =>
    out
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);

  // Containers first: a network can't be removed while something is still
  // attached to it, and `rm -f` stops running orphans as well as dead ones.
  try {
    const names = lines(
      await docker(["ps", "-a", "--filter", "name=^mcpg-", "--format", "{{.Names}}"])
    );
    for (const name of names) {
      await dockerBestEffort(["rm", "-f", name]);
      result.containers.push(name);
    }
  } catch {
    // Listing failed — leave containers unreported rather than guessing.
  }

  // Netfilter state, but only if the helper image already exists: building
  // it here would make every SSE-only run pay for an image it never uses,
  // and if it was never built then no scan ever installed a chain on this
  // machine, so there is nothing to find.
  let helperPresent = true;
  try {
    await execFileAsync("docker", ["image", "inspect", NET_HELPER_IMAGE]);
  } catch {
    helperPresent = false;
  }
  if (helperPresent) {
    // Jumps before chains: iptables refuses to delete a chain that is still
    // referenced. Rules are turned back into delete commands by rewriting
    // `-A` to `-D`, so whatever subnet the orphan used is matched exactly
    // without this process having to remember it.
    const script = [
      `for parent in DOCKER-USER INPUT; do`,
      `  iptables -S "$parent" 2>/dev/null | grep -- '-j MCPG-' | sed 's/^-A /-D /' | while read -r rule; do`,
      `    iptables $rule 2>/dev/null && echo "jump:$(echo "$rule" | sed 's/^-D//')";`,
      `  done;`,
      `done;`,
      `for chain in $(iptables -S 2>/dev/null | sed -n 's/^-N \\(MCPG-.*\\)$/\\1/p'); do`,
      `  iptables -F "$chain" 2>/dev/null;`,
      `  iptables -X "$chain" 2>/dev/null && echo "chain: $chain";`,
      `done`,
    ].join(" ");
    try {
      const out = await docker([
        "run",
        "--rm",
        "--network",
        "host",
        "--cap-add=NET_ADMIN",
        "--cap-add=NET_RAW",
        NET_HELPER_IMAGE,
        "sh",
        "-c",
        script,
      ]);
      result.iptables.push(...lines(out));
    } catch {
      // Same posture as teardown(): sweeping is defensive, and a failure
      // here must not block the scan the user actually asked for.
    }
  }

  try {
    const ids = lines(
      await docker(["network", "ls", "--filter", "name=^mcpg-net-", "--format", "{{.Name}}"])
    );
    for (const name of ids) {
      await dockerBestEffort(["network", "rm", name]);
      result.networks.push(name);
    }
  } catch {
    // As above — nothing reported rather than a guess.
  }

  return result;
}
