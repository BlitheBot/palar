/**
 * Docker-based isolation for `mcpguard live`'s stdio targets. This is what
 * makes connector.ts's spawn a contained one: the target's declared
 * command/args run inside an ephemeral, network-restricted container
 * instead of directly on this host. See README.md's "Live scanning"
 * section for what this does and doesn't cover.
 *
 * Two things below were verified empirically (not assumed) against a
 * native Linux Docker Engine daemon and don't match what's commonly
 * documented for Docker Desktop:
 *
 *   - A host listener bound to 127.0.0.1 is NOT reachable from a container,
 *     even via `--add-host=host.docker.internal:host-gateway` — a socket
 *     bound to loopback only accepts loopback-origin connections. The
 *     oracle must bind to the scan's own bridge network's gateway address
 *     instead (see liveScan.ts, which does this via `gatewayIp`).
 *   - `--add-host=host.docker.internal:host-gateway` resolves to the
 *     *default* `docker0` bridge's gateway on native Linux Engine, not to
 *     whatever custom bridge network the container is actually attached
 *     to. dockerRunArgs() below passes the scan network's real gateway IP
 *     as a literal address instead of relying on the "host-gateway" magic
 *     value, which is correct on both Docker Desktop and native Engine.
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

export class TargetSandbox {
  readonly id: string;
  readonly networkName: string;
  readonly containerName: string;
  readonly chainName: string;
  readonly gatewayIp: string;
  readonly subnet: string;

  private firewallInstalled = false;
  private torn = false;

  private constructor(id: string, networkName: string, net: NetworkInfo) {
    this.id = id;
    this.networkName = networkName;
    this.containerName = `mcpg-${id}`;
    this.chainName = `MCPG-${id}`;
    this.gatewayIp = net.gatewayIp;
    this.subnet = net.subnet;
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
    return new TargetSandbox(id, networkName, net);
  }

  /**
   * Installs egress control: a per-scan MCPG-<id> chain (ACCEPT to the
   * oracle's port on this network's gateway address, REJECT everything
   * else) plus a single jump rule inserted into the shared DOCKER-USER
   * chain. Keeping the ACCEPT/REJECT pair in a scan-owned chain, rather
   * than inline in DOCKER-USER, limits concurrent-scan interference to
   * that one jump-rule insert/delete — still shared, host-global mutable
   * state, but a much smaller footprint than editing DOCKER-USER directly.
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
      `iptables -A ${this.chainName} -d ${this.gatewayIp} -p tcp --dport ${oraclePort} -j ACCEPT`,
      `iptables -A ${this.chainName} -j REJECT`,
      `iptables -I DOCKER-USER -s ${this.subnet} -j ${this.chainName}`,
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
      "--add-host",
      `host.docker.internal:${this.gatewayIp}`,
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
      // chain got created but the DOCKER-USER jump never landed), and an
      // early failure here (e.g. "no such rule" deleting a jump that was
      // never inserted) must not skip flushing/deleting the chain itself.
      const script = [
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
