/**
 * Docker-based isolation for `palar live`'s stdio targets. This is what
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
 * trusting the containment claims. Both backends have now been exercised
 * end-to-end, but by different means and with different freshness:
 *
 *   - Native Linux Engine: verified continuously by
 *     .github/workflows/canary.yml, which runs daily on a GitHub-hosted
 *     ubuntu-latest runner — a full VM on native Docker Engine, so
 *     isDockerDesktop() returns false and this is the branch that actually
 *     executes there. It asserts a *pair* of results that only hold
 *     together if netfilter is genuinely discriminating: the oracle
 *     callback lands (positive control — the sandbox reached the host on
 *     the one ACCEPTed port) while a host listener verified up on a
 *     sentinel port is unreachable from that same container (negative
 *     control). Either alone proves nothing. It also asserts DNS does not
 *     resolve inside the sandbox, and that no container, network, MCPG-*
 *     chain or lock file survives teardown. The latest run measured exactly
 *     that: 1 confirmed callback, sentinel connect refused, DNS lookup
 *     failed in 17ms, container found and probed, bridge gateway
 *     172.18.0.1.
 *   - Docker Desktop (Windows/WSL2): verified by hand as of 2026-07-30
 *     (commit 5ba1a5f, which added the INPUT hook and BLACKHOLE_DNS), not
 *     continuously. The same three observations (host-namespace listener
 *     unreachable, DNS resolution failing, oracle callback still landing)
 *     were made empirically by dumping live netfilter state mid-scan and
 *     probing from a second shell. That date is the age of the evidence:
 *     nothing has re-checked it since, and nothing will on its own.
 *
 * That asymmetry is structural, not an unfinished chore. Docker Desktop
 * cannot get an equivalent canary because no hosted CI runner offers that
 * backend — GitHub's are native-Engine VMs, which is exactly why the canary
 * exercises the Linux path — and Docker Desktop's licence and its
 * VM-in-a-VM requirements rule out installing it on one. So the backend
 * whose containment depends on the most Docker-Desktop-specific machinery
 * (host.docker.internal, the host-proxy IP resolved in
 * resolveDockerDesktopHostProxyIp) is the one whose verification can only
 * ever be re-established by hand, and it ages from the date above until
 * someone does.
 *
 * What the canary does NOT establish: it exercises exactly one host
 * netfilter configuration — Ubuntu 24.04, where `iptables` is the nft-backed
 * shim and dockerd follows it. Its backend-agreement probe proves the
 * net-helper image and the host agree on that one distro; it says nothing
 * about hosts that resolve `iptables` to the legacy backend, or about hosts
 * with no iptables compatibility layer at all, where these rules may not
 * apply as written. Re-run the same checks before relying on the sandbox
 * there.
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import type { MCPServerConfig } from "../core/types.js";
import type { ScanLock } from "./lock.js";
import { buildCleanEnv } from "./env.js";

const execFileAsync = promisify(execFile);

const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url));
const TARGET_RUNTIME_DIR = join(REPO_ROOT, "docker", "target-runtime");
const NET_HELPER_DIR = join(REPO_ROOT, "docker", "net-helper");
const TARGET_RUNTIME_IMAGE = "palar-target-runtime:local";
const NET_HELPER_IMAGE = "palar-net-helper:local";

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
 * instantly instead of burning ~10s of resolver timeouts per lookup
 * (measured both ways). The canary measures the fast path directly on
 * native Linux Engine — 17ms to a failed lookup, against a 5s probe budget.
 *
 * Two different error codes describe that one failure, and which one you
 * see depends on where you look. At the socket layer the UDP datagram to
 * 127.0.0.1:53 draws an immediate ICMP port-unreachable, i.e. ECONNREFUSED
 * — that is what makes it fast, and it is why this address was chosen.
 * But getaddrinfo() does not pass that through: it maps the refusal to
 * EAI_AGAIN, so EAI_AGAIN is what a target, a log line, or a probe actually
 * observes. Both are correct; only the second is visible.
 *
 * Worth spelling out because the invisible one is the one people search
 * for: someone debugging a suspected blackhole failure naturally greps for
 * ECONNREFUSED, finds nothing, and concludes the mitigation isn't working —
 * when EAI_AGAIN arriving in milliseconds is exactly what success looks
 * like. A slow EAI_AGAIN is the shape that should worry you, not the code
 * itself.
 *
 * A target could of course bind its own resolver there and answer itself,
 * which gains it nothing — every address it could resolve to is still
 * REJECTed by the egress chain.
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

/**
 * Builds the image if it is not already present, announcing it when it is
 * actually going to build.
 *
 * The announcement is not decoration. A first run has to fetch a ~300MB
 * base layer and install a package into it, which can take minutes on a
 * slow link — and the only feedback was silence, followed (if it ran long
 * enough) by a timeout that blamed the target. `onBuild` lets the caller
 * say what is happening; nothing else about the build changes.
 */
async function ensureImageBuilt(
  image: string,
  contextDir: string,
  onBuild?: (image: string) => void
): Promise<void> {
  try {
    await execFileAsync("docker", ["image", "inspect", image]);
    return;
  } catch {
    // Not present locally — fall through to build.
  }
  onBuild?.(image);
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
      "palar live requires Docker to sandbox stdio targets, but `docker version` failed " +
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

/**
 * The `iptables` script installFirewall() runs, as a pure function of its
 * inputs.
 *
 * Split out of installFirewall() so the *contents* of the rules can be
 * asserted without a Docker daemon. The claim that an enumeration-only
 * scan opens no hole in the egress firewall is a security claim, and a
 * security claim that can only be checked by running Docker is a claim
 * that mostly isn't checked.
 */
export function buildFirewallScript(spec: {
  chainName: string;
  subnet: string;
  hostReachableIp: string;
  allowPort: number | null;
}): string {
  return [
    `iptables -N ${spec.chainName}`,
    // Ordering matters: the ACCEPT, when there is one, must precede the
    // catch-all REJECT. With allowPort === null the chain is REJECT-only.
    ...(spec.allowPort === null
      ? []
      : [
          `iptables -A ${spec.chainName} -d ${spec.hostReachableIp} -p tcp ` +
            `--dport ${spec.allowPort} -j ACCEPT`,
        ]),
    `iptables -A ${spec.chainName} -j REJECT`,
    `iptables -I DOCKER-USER -s ${spec.subnet} -j ${spec.chainName}`,
    `iptables -I INPUT -s ${spec.subnet} -j ${spec.chainName}`,
  ].join(" && ");
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
  static async create(onBuild?: (image: string) => void): Promise<TargetSandbox> {
    await preflightDocker();
    await ensureImageBuilt(TARGET_RUNTIME_IMAGE, TARGET_RUNTIME_DIR, onBuild);
    await ensureImageBuilt(NET_HELPER_IMAGE, NET_HELPER_DIR, onBuild);

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
   * Installs egress control: a per-scan MCPG-<id> chain (REJECT everything,
   * preceded by an ACCEPT for one host port when — and only when — this
   * scan actually needs one) plus jump rules into two shared chains.
   * Keeping the ACCEPT/REJECT pair in a scan-owned chain, rather than
   * inline in those chains, limits concurrent-scan interference to the
   * jump-rule insert/delete — still shared, host-global mutable state, but
   * a much smaller footprint than editing them directly.
   *
   * `allowPort` is the oracle's port for a probing scan (`palar live`),
   * which has to be able to receive its own out-of-band callback, and
   * `null` for an enumeration-only scan (`palar scan --from-command`),
   * which never calls a tool and therefore never needs a callback to
   * arrive. Passing `null` installs the chain with **no ACCEPT hole at
   * all**: nothing the container originates is permitted anywhere. That is
   * strictly tighter than the probing case, and it is the default posture
   * for any caller that does not have a specific reason to open a port —
   * which is why the parameter is `number | null` rather than optional. An
   * omitted argument would silently mean "no hole" for a caller that
   * needed one, and the failure mode of a *missing* ACCEPT is a probe that
   * reports UNCONFIRMED rather than an error, i.e. a wrong answer that
   * looks like a right one. Making the choice explicit at every call site
   * removes that shape entirely.
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
  async installFirewall(allowPort: number | null): Promise<void> {
    // Runtime half of the `number | null` contract above. TypeScript makes
    // an omitted argument a compile error, but a JS caller (or an `as any`)
    // still reaches here with `undefined`, and "undefined" must not quietly
    // degrade into either interpretation — neither a missing ACCEPT for a
    // scan that needed one, nor a hole opened on port NaN.
    if (allowPort !== null && !Number.isInteger(allowPort)) {
      throw new SandboxError(
        "installFirewall() requires an explicit allow-port: a port number for a scan that must " +
          "receive an oracle callback, or null for an enumeration-only scan that needs no egress " +
          `at all (got ${String(allowPort)})`
      );
    }

    // Set before the script runs, not after it succeeds: if a later step in
    // the chain (e.g. the DOCKER-USER jump) fails after an earlier one
    // (e.g. `iptables -N`) already created state, teardown() still needs to
    // know there's something to clean up. teardown()'s own cleanup script
    // is independently best-effort per step, so attempting it against
    // partially-created state is always safe.
    this.firewallInstalled = true;
    const script = buildFirewallScript({
      chainName: this.chainName,
      subnet: this.subnet,
      hostReachableIp: this.hostReachableIp,
      allowPort,
    });
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
   *
   * Refuses outright if installFirewall() has not run. This is the single
   * chokepoint through which a target can be started at all — the argv it
   * returns is the only thing connector.ts ever hands to `docker` — so
   * putting the check here is what makes "the firewall cannot be skipped"
   * a property of the code rather than of caller discipline. A caller that
   * forgets, or a new call path added later that never learned the
   * convention, gets a hard error instead of an unfirewalled container
   * with full network reach that otherwise looks like a normal scan.
   */
  dockerRunArgs(server: MCPServerConfig, targetDir: string): string[] {
    if (!this.firewallInstalled) {
      throw new SandboxError(
        `refusing to build a container command line for "${server.name}" before installFirewall() ` +
          "has run — the target would start with unrestricted network egress. Call " +
          "installFirewall(port) for a scan that needs an oracle callback, or installFirewall(null) " +
          "for an enumeration-only scan."
      );
    }
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
   * Blocks until this scan's container is actually running, and reports how
   * long that took.
   *
   * This exists to fix what `--connect-timeout-ms` MEASURES. The container
   * is started by the stdio transport spawning `docker run`, so everything
   * between that spawn and the daemon actually having a process — image
   * layer extraction, a cold Docker Desktop VM waking up, WSL2 doing
   * whatever WSL2 does — used to be charged to a budget named for the
   * target's responsiveness. It is not the target's fault and it is not the
   * target's behaviour, and the failure it produced said "never reached"
   * about a server that had not been asked anything yet.
   *
   * Polling the daemon rather than watching the pipe because "the container
   * is running" is a fact the daemon owns and will state; inferring it from
   * the absence of output would be guessing.
   *
   * `abandoned` lets the caller stop the poll early — it is raced against
   * the connect itself, so a target that answers (or dies) immediately is
   * never held up by this. The container runs with `--rm`, so a container
   * that started and exited is indistinguishable from one not yet created;
   * both keep polling, and the connect failure that follows carries the
   * target's own stderr, which is the more useful error either way.
   */
  async waitForContainerRunning(
    timeoutMs: number,
    abandoned: () => boolean = () => false
  ): Promise<number> {
    const start = Date.now();
    for (;;) {
      if (abandoned()) return Date.now() - start;
      try {
        const out = await execFileAsync("docker", [
          "inspect",
          "--format",
          "{{.State.Running}}",
          this.containerName,
        ]);
        if (out.stdout.trim() === "true") return Date.now() - start;
      } catch {
        // No such container yet (or already reaped by --rm). Keep waiting.
      }
      if (Date.now() - start >= timeoutMs) {
        throw new SandboxError(
          `the sandbox container ${this.containerName} was not running ${timeoutMs}ms after ` +
            "`docker run` was invoked. This is palar's own container start, not the target " +
            "answering — a cold Docker daemon can take a while. Raise " +
            "--container-start-timeout-ms if this machine is consistently slow."
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
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
 * Concurrency: this treats every `mcpg-`/`MCPG-` object as orphaned, and
 * that is correct rather than merely expedient — but only because of an
 * invariant enforced elsewhere. This function cannot itself tell a crashed
 * run's leftovers from a concurrent run's live state (a container left
 * running by Ctrl-C looks exactly like one a healthy concurrent scan is
 * using), so the CLI removes the ambiguity instead of resolving it: it
 * holds the host-wide live-scan lock (live/lock.ts) across this call and
 * the entire scan that follows, which means no second palar live scan can
 * exist to own any of it.
 *
 * **Callers must hold that lock**, which is why one is a required
 * parameter rather than a documented precondition: without it this would
 * happily reclaim a running scan's container and delete its egress
 * firewall. The `lock` argument is not otherwise used — it exists so the
 * compiler refuses a call that cannot prove the invariant, and so
 * assertHeld() can catch the case the type system can't see (a lock object
 * that was legitimately obtained but has since been released).
 *
 * The lock is host-local, so the one uncovered case is two machines
 * pointed at the same remote Docker daemon — see README's named gaps.
 */
export async function sweepOrphanedSandboxState(lock: ScanLock): Promise<SweepResult> {
  lock.assertHeld("sweepOrphanedSandboxState()");

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
    //
    // This matches EVERY `-j MCPG-` rule and every MCPG-* chain, with no
    // scan-id discrimination — deliberately, and safe by construction
    // rather than by luck. The CLI takes the host-wide live-scan lock
    // (live/lock.ts) before calling this and holds it for the whole run,
    // and that lock is what guarantees no other palar live scan can be
    // running on this host. So every MCPG-* object netfilter still has is
    // necessarily a crashed run's leftovers, never a concurrent scan's live
    // firewall. Without the lock this wildcard would be actively dangerous:
    // it would strip a running scan's ACCEPT/REJECT pair and leave its
    // sandbox container up with unrestricted egress.
    //
    // If that lock is ever removed, relaxed to allow concurrent scans, or
    // this function grows a caller that doesn't hold it, this script MUST
    // become id-scoped first. The one case the lock does not cover is two
    // separate machines sharing one remote Docker daemon (pids aren't
    // comparable across hosts) — a documented limitation, see README.
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
