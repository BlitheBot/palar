import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { sweepOrphanedSandboxState, type SweepResult } from "./sandbox.js";
import { ScanLock, type ProcessProbe } from "./lock.js";

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
