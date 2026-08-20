import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildFirewallScript,
  sweepOrphanedSandboxState,
  TargetSandbox,
  type SweepResult,
} from "./sandbox.js";
import { ScanLock, type ProcessProbe } from "./lock.js";
import type { MCPServerConfig } from "../core/types.js";

const aliveProbe: ProcessProbe = async (pid) =>
  pid === process.pid ? { alive: true, startedAt: "self-start" } : { alive: false };

async function heldLock(): Promise<{ lock: ScanLock; dir: string }> {
  const dir = await mkdtemp(join(tmpdir(), "palar-sweep-test-"));
  const lock = await ScanLock.acquire({ stateDir: dir, probeProcess: aliveProbe });
  return { lock, dir };
}

/**
 * The type-level half of the contract. This function is deliberately never
 * called — it exists so that `tsc` has to check the call, and the
 * @ts-expect-error fails the build if sweepOrphanedSandboxState() ever
 * stops requiring a ScanLock. That makes "you must hold the lock" a
 * compile error rather than a comment someone can miss.
 */
export function _sweepRequiresALockAtCompileTime(): void {
  // @ts-expect-error - sweepOrphanedSandboxState() must not be callable without a ScanLock
  const withoutLock: () => Promise<SweepResult> = () => sweepOrphanedSandboxState();
  // @ts-expect-error - and not with something that merely looks lock-shaped
  const withFake: () => Promise<SweepResult> = () => sweepOrphanedSandboxState({ held: true });
  void withoutLock;
  void withFake;
}

test("sweep cannot be invoked without a lock object", async () => {
  // Runtime counterpart to the compile-time check above: the type system
  // is erased at runtime, so a JS caller (or an `as any` cast) can still
  // get here. It must fail loudly rather than sweep unprotected.
  const sweepUntyped = sweepOrphanedSandboxState as unknown as (
    lock?: unknown
  ) => Promise<SweepResult>;

  await assert.rejects(() => sweepUntyped(), TypeError);
  await assert.rejects(() => sweepUntyped(undefined), TypeError);
  await assert.rejects(() => sweepUntyped(null), TypeError);
  // Lock-shaped but not a lock: no assertHeld to call.
  await assert.rejects(() => sweepUntyped({ held: true }), TypeError);
});

test("sweep refuses a lock that has already been released", async () => {
  const { lock, dir } = await heldLock();
  try {
    await lock.release();
    assert.equal(lock.held, false);

    // Must throw before touching Docker at all — a released lock is
    // exactly as unsafe to sweep under as no lock.
    await assert.rejects(
      () => sweepOrphanedSandboxState(lock),
      (err: unknown) => {
        assert.match(
          (err as Error).message,
          /requires the live-scan lock to still be held/
        );
        assert.match((err as Error).message, /sweepOrphanedSandboxState\(\)/);
        return true;
      }
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("assertHeld passes while the lock is held and fails after release", async () => {
  const { lock, dir } = await heldLock();
  try {
    assert.equal(lock.held, true);
    assert.doesNotThrow(() => lock.assertHeld("test"));

    await lock.release();

    assert.equal(lock.held, false);
    assert.throws(() => lock.assertHeld("test"), /already been released/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

/**
 * A TargetSandbox with its fields set directly, so the rules and guards
 * below can be checked without a Docker daemon. The constructor is private
 * to keep production code going through create(); `private` is erased at
 * runtime, and a test that can only run where Docker is installed is a test
 * that does not run.
 */
function offlineSandbox(): TargetSandbox {
  const sandbox = Object.create(TargetSandbox.prototype) as TargetSandbox & {
    id: string;
    networkName: string;
    containerName: string;
    chainName: string;
    gatewayIp: string;
    subnet: string;
    isDockerDesktop: boolean;
    hostReachableIp: string;
    oracleBindHost: string;
    firewallInstalled: boolean;
    torn: boolean;
  };
  Object.assign(sandbox, {
    id: "deadbeef",
    networkName: "mcpg-net-deadbeef",
    containerName: "mcpg-deadbeef",
    chainName: "MCPG-deadbeef",
    gatewayIp: "172.18.0.1",
    subnet: "172.18.0.0/16",
    isDockerDesktop: false,
    hostReachableIp: "172.18.0.1",
    oracleBindHost: "172.18.0.1",
    firewallInstalled: false,
    torn: false,
  });
  return sandbox;
}

const SPEC = {
  chainName: "MCPG-deadbeef",
  subnet: "172.18.0.0/16",
  hostReachableIp: "172.18.0.1",
};

test("an enumeration-only scan installs the chain with no ACCEPT hole at all", () => {
  const script = buildFirewallScript({ ...SPEC, allowPort: null });

  // The security claim `scan --from-command` makes, asserted directly:
  // nothing the container originates is permitted anywhere. Enumeration
  // calls no tool, so no callback ever needs to arrive.
  assert.ok(!script.includes("ACCEPT"), `expected no ACCEPT rule, got: ${script}`);
  assert.match(script, /iptables -A MCPG-deadbeef -j REJECT/);
  // The chain still has to be wired into both shared chains — a REJECT-all
  // chain nothing jumps to filters nothing.
  assert.match(script, /iptables -I DOCKER-USER -s 172\.18\.0\.0\/16 -j MCPG-deadbeef/);
  assert.match(script, /iptables -I INPUT -s 172\.18\.0\.0\/16 -j MCPG-deadbeef/);
});

test("a probing scan opens exactly one port, and the ACCEPT precedes the REJECT", () => {
  const script = buildFirewallScript({ ...SPEC, allowPort: 54321 });
  const accept = script.indexOf("-j ACCEPT");
  const reject = script.indexOf("-j REJECT");

  assert.ok(accept > -1 && reject > -1);
  // Order is the whole rule: an ACCEPT after a catch-all REJECT is dead.
  assert.ok(accept < reject, `ACCEPT must precede REJECT, got: ${script}`);
  assert.match(script, /-d 172\.18\.0\.1 -p tcp --dport 54321 -j ACCEPT/);
  assert.equal(script.match(/ACCEPT/g)?.length, 1);
});

test("installFirewall rejects an omitted allow-port rather than guessing", async () => {
  // TypeScript makes this a compile error; a JS caller still gets here, and
  // "undefined" must not degrade into either interpretation. A missing
  // ACCEPT for a scan that needed one fails as UNCONFIRMED — a wrong answer
  // that looks like a right one.
  const sandbox = offlineSandbox();
  const untyped = sandbox.installFirewall as unknown as (p?: unknown) => Promise<void>;

  await assert.rejects(() => untyped.call(sandbox), /requires an explicit allow-port/);
  await assert.rejects(() => untyped.call(sandbox, undefined), /requires an explicit allow-port/);
  await assert.rejects(() => untyped.call(sandbox, "4000"), /requires an explicit allow-port/);
});

test("the firewall cannot be skipped: dockerRunArgs refuses before it is installed", () => {
  const sandbox = offlineSandbox();
  const server: MCPServerConfig = { name: "t", command: "node", args: ["/target/i.js"] };

  // dockerRunArgs() is the only route to starting a target, so this is what
  // makes "always sandboxed" a property of the code rather than of caller
  // discipline — including for call paths added later.
  assert.throws(
    () => sandbox.dockerRunArgs(server, "/tmp/x"),
    /refusing to build a container command line .* before installFirewall\(\) has run/s
  );

  (sandbox as unknown as { firewallInstalled: boolean }).firewallInstalled = true;
  const args = sandbox.dockerRunArgs(server, "/tmp/x");
  assert.ok(args.includes("--read-only"));
  assert.ok(args.includes("--cap-drop=ALL"));
});
