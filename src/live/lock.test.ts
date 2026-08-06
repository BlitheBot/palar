import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, writeFile, rm, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir, hostname } from "node:os";
import { join } from "node:path";
import {
  ScanLock,
  ScanLockHeldError,
  classifyHolder,
  resolveStateDir,
  type LockRecord,
  type ProcessProbe,
} from "./lock.js";

const LOCK_FILENAME = "live-scan.lock";

async function stateDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "palar-lock-test-"));
}

/**
 * A probe backed by a plain map, so every liveness branch is exercised
 * without spawning real processes or waiting on real pids. `undefined`
 * means "no such process"; a string is that pid's start-time token.
 */
function fakeProbe(live: Record<number, string | null>): ProcessProbe {
  return async (pid) => {
    if (!(pid in live)) return { alive: false };
    return { alive: true, startedAt: live[pid] ?? null };
  };
}

/** Writes a lock file directly, standing in for a previous run's holder. */
async function writeLock(dir: string, record: Partial<LockRecord>): Promise<string> {
  const path = join(dir, LOCK_FILENAME);
  const full: LockRecord = {
    pid: 4242,
    procStartTime: "1000",
    createdAt: "2026-01-01T00:00:00.000Z",
    hostname: hostname(),
    ...record,
  };
  await writeFile(path, JSON.stringify(full, null, 2), "utf8");
  return path;
}

test("acquires cleanly when no lock file exists, and writes its own record", async () => {
  const dir = await stateDir();
  try {
    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    assert.equal(lock.reclaimed, null);

    const onDisk = JSON.parse(await readFile(join(dir, LOCK_FILENAME), "utf8")) as LockRecord;
    assert.equal(onDisk.pid, process.pid);
    assert.equal(onDisk.procStartTime, "self-start");
    assert.equal(onDisk.hostname, hostname());
    await lock.release();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("refuses when a live pid with a matching start time holds the lock", async () => {
  const dir = await stateDir();
  try {
    await writeLock(dir, { pid: 4242, procStartTime: "1000" });

    await assert.rejects(
      () =>
        ScanLock.acquire({
          stateDir: dir,
          probeProcess: fakeProbe({ 4242: "1000", [process.pid]: "self-start" }),
        }),
      (err: unknown) => {
        assert.ok(err instanceof ScanLockHeldError);
        assert.match(err.message, /another palar live scan is running/);
        assert.match(err.message, /pid 4242/);
        assert.match(err.message, /2026-01-01T00:00:00\.000Z/);
        return true;
      }
    );

    // The live holder's lock must survive our refusal untouched.
    const onDisk = JSON.parse(await readFile(join(dir, LOCK_FILENAME), "utf8")) as LockRecord;
    assert.equal(onDisk.pid, 4242);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("reclaims the lock when the recorded holder is dead", async () => {
  const dir = await stateDir();
  try {
    await writeLock(dir, { pid: 4242, procStartTime: "1000" });

    // 4242 absent from the probe map: the process is gone (SIGKILL, crash).
    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });

    assert.match(lock.reclaimed ?? "", /pid 4242 is no longer running/);
    const onDisk = JSON.parse(await readFile(join(dir, LOCK_FILENAME), "utf8")) as LockRecord;
    assert.equal(onDisk.pid, process.pid);
    await lock.release();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("reclaims the lock when the pid was reused by a different process", async () => {
  const dir = await stateDir();
  try {
    await writeLock(dir, { pid: 4242, procStartTime: "1000" });

    // 4242 exists, but started at a different time — the original holder
    // died and the OS recycled its pid onto something unrelated.
    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ 4242: "9999", [process.pid]: "self-start" }),
    });

    assert.match(lock.reclaimed ?? "", /pid 4242 was reused by a different process/);
    const onDisk = JSON.parse(await readFile(join(dir, LOCK_FILENAME), "utf8")) as LockRecord;
    assert.equal(onDisk.pid, process.pid);
    await lock.release();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("treats an alive holder with an unknown start time as live, not stale", async () => {
  const dir = await stateDir();
  try {
    await writeLock(dir, { pid: 4242, procStartTime: "1000" });

    // Alive, but the start-time shim could not read it (EPERM, shim
    // failure). PID reuse cannot be ruled out, so the safe answer is to
    // refuse rather than break a possibly-live scan's lock.
    await assert.rejects(
      () =>
        ScanLock.acquire({
          stateDir: dir,
          probeProcess: fakeProbe({ 4242: null, [process.pid]: "self-start" }),
        }),
      ScanLockHeldError
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("treats a malformed lock file as stale and reclaims it", async () => {
  const dir = await stateDir();
  try {
    await writeFile(join(dir, LOCK_FILENAME), "{ not json at all", "utf8");

    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });

    assert.match(lock.reclaimed ?? "", /unreadable or malformed/);
    await lock.release();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("refuses a lock written by a different host rather than guessing", async () => {
  const dir = await stateDir();
  try {
    await writeLock(dir, { pid: 4242, hostname: "some-other-machine" });

    await assert.rejects(
      () =>
        ScanLock.acquire({
          stateDir: dir,
          // Even though pid 4242 is dead *here*, the record is from
          // another host where that pid means something else entirely.
          probeProcess: fakeProbe({ [process.pid]: "self-start" }),
        }),
      (err: unknown) => {
        assert.ok(err instanceof ScanLockHeldError);
        assert.match(err.message, /written by a different host/);
        assert.match(err.message, /some-other-machine/);
        return true;
      }
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("release removes the lock file, and is idempotent", async () => {
  const dir = await stateDir();
  try {
    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    assert.ok(existsSync(join(dir, LOCK_FILENAME)));

    await lock.release();
    assert.ok(!existsSync(join(dir, LOCK_FILENAME)));

    // Second release must not throw, and must not delete anything that a
    // subsequent scan has since created.
    await lock.release();
    assert.ok(!existsSync(join(dir, LOCK_FILENAME)));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("release does not delete a lock that now belongs to another scan", async () => {
  const dir = await stateDir();
  try {
    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });

    // Simulate our lock having been broken as stale and replaced by a
    // different, live scan's record while we were still running.
    await writeLock(dir, { pid: 5555, procStartTime: "2000" });

    await lock.release();

    const onDisk = JSON.parse(await readFile(join(dir, LOCK_FILENAME), "utf8")) as LockRecord;
    assert.equal(onDisk.pid, 5555, "the other scan's lock must survive our release");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("releaseSync removes the lock file the same way (the crash-handler path)", async () => {
  const dir = await stateDir();
  try {
    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    // Counted relative to whatever the test runner itself has registered,
    // rather than asserting an absolute zero.
    const exitListenersBefore = process.listenerCount("exit");
    lock.installCrashHandlers();
    assert.equal(process.listenerCount("exit"), exitListenersBefore + 1);
    assert.ok(existsSync(join(dir, LOCK_FILENAME)));

    // What the 'exit' / SIGINT handlers invoke.
    lock.releaseSync();
    assert.ok(!existsSync(join(dir, LOCK_FILENAME)));

    // And it must have unregistered its handlers, so a released lock can't
    // fire again at process exit.
    assert.equal(process.listenerCount("exit"), exitListenersBefore);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a lock left behind by a SIGKILLed run is reclaimed by the next acquire", async () => {
  const dir = await stateDir();
  try {
    // A hard-killed process never runs any handler, so its lock file
    // survives verbatim with its own pid and start time in it.
    const crashed = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    void crashed; // never released — this is the crash

    assert.ok(existsSync(join(dir, LOCK_FILENAME)));

    // Next run: the crashed holder's pid no longer resolves.
    const next = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ 777: "next-start" }),
      // The crashed record's pid is process.pid, which is absent above.
    });

    assert.match(next.reclaimed ?? "", /no longer running/);
    await next.release();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("acquire creates the state directory if it does not exist", async () => {
  const parent = await stateDir();
  const nested = join(parent, "deeper", "palar");
  try {
    const lock = await ScanLock.acquire({
      stateDir: nested,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    assert.ok(existsSync(join(nested, LOCK_FILENAME)));
    await lock.release();
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("classifyHolder reports a missing record as stale without probing", async () => {
  const verdict = await classifyHolder(null, async () => {
    throw new Error("probe must not be called for a missing record");
  });
  assert.equal(verdict.state, "stale");
});

test("classifyHolder rejects a record whose pid is not an integer", async () => {
  const verdict = await classifyHolder(
    { pid: "nope" as unknown as number, procStartTime: "1", createdAt: "", hostname: hostname() },
    async () => ({ alive: true, startedAt: "1" })
  );
  assert.equal(verdict.state, "stale");
});

test("the state directory is a real app state dir, never os.tmpdir()", async () => {
  const dir = resolveStateDir();
  assert.ok(
    !dir.startsWith(tmpdir()),
    `state dir ${dir} must not live under the OS temp dir (tmp cleaners delete live locks)`
  );
  assert.match(dir, /palar$/);

  if (process.platform === "win32") {
    assert.match(dir, /AppData[\\/]Local/i);
  } else {
    // XDG_STATE_HOME when set, else the spec's ~/.local/state fallback.
    const expectedBase = process.env.XDG_STATE_HOME;
    if (expectedBase) assert.ok(dir.startsWith(expectedBase));
    else assert.match(dir, /\.local[\\/]state/);
  }
});

test("two sequential acquires against one directory serialize correctly", async () => {
  const dir = await stateDir();
  try {
    const first = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });

    // A second acquire while the first is genuinely held (our own pid, so
    // the probe reports it alive with a matching start time) must refuse.
    await assert.rejects(
      () =>
        ScanLock.acquire({
          stateDir: dir,
          probeProcess: fakeProbe({ [process.pid]: "self-start" }),
        }),
      ScanLockHeldError
    );

    await first.release();

    // Once released, the next acquire succeeds with nothing reclaimed.
    const second = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    assert.equal(second.reclaimed, null);
    await second.release();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the lock file is never observable in a partially-written state", async () => {
  const dir = await stateDir();
  try {
    // Poll the lock path as hard as the event loop allows while an acquire
    // is in flight. Every sighting must already be complete and parseable —
    // the create-then-write shape would be caught here as a zero-byte read.
    const sightings: string[] = [];
    let polling = true;
    const poller = (async () => {
      while (polling) {
        try {
          sightings.push(await readFile(join(dir, LOCK_FILENAME), "utf8"));
        } catch {
          // Not created yet, or already gone — neither is a partial write.
        }
        await new Promise((r) => setImmediate(r));
      }
    })();

    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    polling = false;
    await poller;

    assert.ok(sightings.length > 0, "expected to observe the lock file at least once");
    for (const raw of sightings) {
      assert.notEqual(raw, "", "observed a zero-byte lock file — creation is not atomic");
      const parsed = JSON.parse(raw) as LockRecord;
      assert.equal(parsed.pid, process.pid);
    }
    await lock.release();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("acquire leaves no temp files behind", async () => {
  const dir = await stateDir();
  try {
    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    const entries = await readdir(dir);
    assert.deepEqual(entries, [LOCK_FILENAME], `unexpected leftovers: ${entries.join(", ")}`);

    await lock.release();
    assert.deepEqual(await readdir(dir), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a lock file that stays unparseable is still eventually treated as stale", async () => {
  const dir = await stateDir();
  try {
    // Genuine corruption (not a mid-write) must not wedge the tool: the
    // re-read gives a half-written file time to finish, then gives up.
    await writeFile(join(dir, LOCK_FILENAME), "", "utf8");

    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    assert.match(lock.reclaimed ?? "", /unreadable or malformed/);
    await lock.release();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("mkdir of an already-existing state directory is not an error", async () => {
  const dir = await stateDir();
  try {
    await mkdir(dir, { recursive: true });
    const lock = await ScanLock.acquire({
      stateDir: dir,
      probeProcess: fakeProbe({ [process.pid]: "self-start" }),
    });
    await lock.release();
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
