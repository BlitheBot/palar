/**
 * A single host-wide exclusive lock serializing `palar live` runs.
 *
 * Why this exists, and why it's a lock rather than per-scan liveness
 * tracking: a live scan's most dangerous state isn't its container or its
 * network (both namespaced and per-scan), it's the netfilter rules it
 * installs into the host-global DOCKER-USER and INPUT chains. Two scans
 * running at once interleave inserts and deletes on those shared chains,
 * and — worse — sweepOrphanedSandboxState()'s netfilter pass matches every
 * `-j MCPG-` rule with no scan-id discrimination, so a second invocation
 * starting up would tear the *live* egress firewall out from under the
 * first, leaving its sandbox running with its REJECT rule gone.
 *
 * Rather than teaching the sweep to tell a crashed run's leftovers from a
 * concurrent run's live state, this makes the ambiguity impossible: hold
 * this lock for the whole run, and every `mcpg-`/`MCPG-` object on the
 * daemon genuinely *is* an orphan, because no other palar live scan can be
 * running to own one. The wildcard sweep becomes correct by construction.
 *
 * Staleness is decided by process identity, never by age. A lock file whose
 * recorded pid is gone — or has been recycled onto a different process,
 * caught by comparing the recorded start time against the live one — is
 * broken and reclaimed. A lock file whose holder is genuinely alive causes
 * a clean refusal. There is no timeout heuristic anywhere in here, because
 * a scan legitimately running longer than any threshold we'd pick must not
 * become reclaimable while it is still firewalling a live container.
 *
 * Named limitation, deliberately not papered over: this lock is
 * **host-local**. It serializes palar invocations on one machine. It does
 * NOT protect two separate machines pointed at the same remote Docker
 * daemon (DOCKER_HOST, a shared TCP/socket endpoint) — pids are not
 * comparable across hosts, and neither machine can see the other's state
 * directory. See README.md's "Live scanning" section.
 */
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync, unlinkSync } from "node:fs";
import { link, mkdir, open, readFile, unlink, writeFile } from "node:fs/promises";
import { homedir, hostname, platform } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { setTimeout as delay } from "node:timers/promises";

const execFileAsync = promisify(execFile);

const LOCK_FILENAME = "live-scan.lock";

/**
 * Bounded because breaking a stale lock is a two-step
 * unlink-then-recreate, and two processes can both observe the same stale
 * lock and race to break it. O_EXCL guarantees only one wins the recreate;
 * the loser sees EEXIST again and re-evaluates, at which point the winner
 * is a genuinely live holder and it refuses correctly. A handful of
 * attempts is plenty for that to settle — this is not a spin-wait.
 */
const MAX_ACQUIRE_ATTEMPTS = 5;

/** What gets persisted in the lock file. */
export interface LockRecord {
  pid: number;
  /**
   * Opaque, platform-specific process start-time token, compared only for
   * equality against a freshly probed one. Never parsed, never ordered.
   * `null` when the platform shim could not determine it (see
   * ProcessStatus) — which downgrades PID-reuse detection but, handled
   * conservatively at the call site, never causes a live lock to be broken.
   */
  procStartTime: string | null;
  createdAt: string;
  hostname: string;
}

/**
 * Result of asking the OS about a pid. Split out from a bare boolean so a
 * process that exists but whose start time is unreadable (EPERM on another
 * user's process, a shim failure) is distinguishable from one that is gone
 * — the two must be treated very differently.
 */
export type ProcessStatus =
  | { alive: false }
  | { alive: true; startedAt: string | null };

/**
 * Injectable so the lock's decision logic is testable without spawning
 * real processes, waiting on real pids, or touching a real Docker daemon.
 */
export type ProcessProbe = (pid: number) => Promise<ProcessStatus>;

export interface AcquireOptions {
  /** Overridden in tests; defaults to the per-user app state directory. */
  stateDir?: string;
  /** Overridden in tests; defaults to the real OS probe. */
  probeProcess?: ProcessProbe;
}

/** Thrown when another live scan genuinely holds the lock. Not a bug — a refusal. */
export class ScanLockHeldError extends Error {
  readonly record: LockRecord;
  constructor(message: string, record: LockRecord) {
    super(message);
    this.name = "ScanLockHeldError";
    this.record = record;
  }
}

/**
 * A proper per-user state directory, not os.tmpdir(): a tmp cleaner
 * deleting a *live* scan's lock mid-run would silently re-open the exact
 * concurrency hole this closes. XDG_STATE_HOME (falling back to the
 * spec's ~/.local/state) on Linux/macOS; %LOCALAPPDATA% on Windows —
 * Local rather than Roaming on purpose, since a roaming profile can
 * synchronize this file to another machine where its pid means nothing.
 */
export function resolveStateDir(): string {
  if (platform() === "win32") {
    const base = process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local");
    return join(base, "palar");
  }
  const base = process.env.XDG_STATE_HOME ?? join(homedir(), ".local", "state");
  return join(base, "palar");
}

/**
 * Linux: /proc/<pid>/stat field 22 (starttime, in clock ticks since boot).
 * Parsed from after the last ')' rather than by splitting the whole line,
 * because field 2 is the executable name and may itself contain spaces and
 * parentheses.
 */
async function linuxStartTime(pid: number): Promise<string | null> {
  try {
    const stat = await readFile(`/proc/${pid}/stat`, "utf8");
    const afterComm = stat.slice(stat.lastIndexOf(")") + 1).trim();
    // After the comm field, field 3 is `state`, so starttime (field 22
    // overall) is index 19 of what remains.
    const field = afterComm.split(/\s+/)[19];
    return field ?? null;
  } catch {
    return null;
  }
}

/**
 * Windows: Get-Process -Id. StartTime is emitted as a FILETIME integer
 * rather than a formatted date so the comparison can't be perturbed by
 * locale or DST rendering.
 */
async function windowsStartTime(pid: number): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `(Get-Process -Id ${pid} -ErrorAction Stop).StartTime.ToFileTimeUtc()`,
      ],
      { windowsHide: true }
    );
    const value = stdout.trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

/** macOS (and any other POSIX without /proc): ps -o lstart=. */
async function psStartTime(pid: number): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("ps", ["-o", "lstart=", "-p", String(pid)]);
    const value = stdout.trim();
    return value.length > 0 ? value : null;
  } catch {
    return null;
  }
}

async function startTimeForPlatform(pid: number): Promise<string | null> {
  switch (platform()) {
    case "win32":
      return windowsStartTime(pid);
    case "linux":
      return linuxStartTime(pid);
    default:
      return psStartTime(pid);
  }
}

/**
 * The real OS probe. Existence is settled by signal 0 first, because it is
 * cheap, synchronous and unambiguous; only then is the (more expensive,
 * possibly subprocess-spawning) start-time shim consulted.
 *
 * EPERM deserves care: it means the pid exists but belongs to another user,
 * so the process is definitively alive even though we may not be able to
 * read its start time. Reporting it as dead would let one user's palar run
 * break another's live lock.
 */
export const probeProcessDefault: ProcessProbe = async (pid) => {
  try {
    process.kill(pid, 0);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return { alive: false };
    if (code !== "EPERM") return { alive: false };
    // EPERM — alive, just not ours to signal.
    return { alive: true, startedAt: await startTimeForPlatform(pid) };
  }
  return { alive: true, startedAt: await startTimeForPlatform(pid) };
};

/** How a lock file found on disk was classified. Exported for tests. */
export type HolderVerdict =
  | { state: "live"; record: LockRecord }
  | { state: "stale"; record: LockRecord | null; reason: string }
  | { state: "foreign"; record: LockRecord };

/**
 * Decides whether an existing lock file represents a running scan or a
 * crashed one's leftovers. Pure with respect to the injected probe, so
 * every branch is unit-testable.
 *
 * Conservative in exactly one direction: anything that leaves genuine doubt
 * about whether the holder is alive resolves to "don't break it". Refusing
 * to start is a recoverable annoyance; breaking a live scan's lock lets a
 * second scan wildcard-sweep the first's firewall away.
 */
export async function classifyHolder(
  record: LockRecord | null,
  probe: ProcessProbe
): Promise<HolderVerdict> {
  if (!record || typeof record.pid !== "number" || !Number.isInteger(record.pid)) {
    return { state: "stale", record: null, reason: "lock file was unreadable or malformed" };
  }

  // A record written on a different machine (a roamed or network-mounted
  // state directory) carries a pid from that machine's namespace, which
  // says nothing about any process here. Neither reclaimable nor a local
  // conflict — surfaced as its own case so the message can say so.
  if (record.hostname && record.hostname !== hostname()) {
    return { state: "foreign", record };
  }

  const status = await probe(record.pid);
  if (!status.alive) {
    return { state: "stale", record, reason: `holder pid ${record.pid} is no longer running` };
  }

  // Both sides known and different: the pid was recycled onto an unrelated
  // process, so the original holder is gone even though the pid resolves.
  if (
    record.procStartTime !== null &&
    status.startedAt !== null &&
    record.procStartTime !== status.startedAt
  ) {
    return {
      state: "stale",
      record,
      reason: `pid ${record.pid} was reused by a different process`,
    };
  }

  // Either both start times agree, or one side is unknown and PID reuse
  // can't be ruled out. Both mean: treat as live, refuse.
  return { state: "live", record };
}

/**
 * How long to wait before re-reading a lock file that parsed as garbage,
 * and how many times. Belt-and-braces behind createLockFile()'s atomic
 * publish: on any filesystem where that had to fall back to the
 * non-atomic path, this is what keeps a half-written *live* lock from
 * being read as corrupt and reclaimed out from under its owner.
 */
const MALFORMED_REREAD_DELAY_MS = 50;
const MALFORMED_REREAD_ATTEMPTS = 3;

async function readRecord(lockPath: string): Promise<LockRecord | null> {
  for (let attempt = 0; attempt < MALFORMED_REREAD_ATTEMPTS; attempt++) {
    let raw: string;
    try {
      raw = await readFile(lockPath, "utf8");
    } catch {
      // ENOENT: released between our EEXIST and this read. Not malformed
      // and not worth re-reading — the caller's retry loop will simply win
      // the O_EXCL create next time around.
      return null;
    }

    try {
      return JSON.parse(raw) as LockRecord;
    } catch {
      // Empty or truncated. Under the atomic path this is genuine
      // corruption and re-reading changes nothing; under the fallback path
      // it may be a live holder mid-write, which a moment's patience
      // resolves. Cheap enough to always pay.
      if (attempt < MALFORMED_REREAD_ATTEMPTS - 1) await delay(MALFORMED_REREAD_DELAY_MS);
    }
  }
  // Still unparseable after re-reading — classifyHolder() treats it as stale.
  return null;
}

/**
 * Publishes the lock file with its content already complete — the file
 * must never be observable at the lock path in a half-written state.
 *
 * `open(path, "wx")` followed by a write is NOT good enough, and that is
 * the subtle part: O_EXCL makes the *creation* atomic, but it creates a
 * zero-byte file that is immediately visible to everyone else, and the
 * content lands in a second syscall afterwards. A concurrent acquirer that
 * reads in that gap sees an empty file, fails to parse it, and concludes
 * the holder's lock is corrupt — i.e. stale — and breaks a lock belonging
 * to a perfectly healthy scan. Making the write a single write() call does
 * not help; the window is between the create and the write, not between
 * writes.
 *
 * So the content is written to a private temp file first and only then
 * given its real name via link(), which is atomic and fails with EEXIST if
 * the name is taken. The lock file therefore has its full, parseable
 * content from the very first instant it exists — there is no
 * observable intermediate state at all. rename() would be atomic too but
 * is unusable here: it silently clobbers an existing destination, which
 * would destroy the mutual exclusion that is the entire point.
 *
 * Returns true if we created the lock, false if someone else already holds
 * the name.
 */
async function createLockFile(lockPath: string, record: LockRecord): Promise<boolean> {
  const payload = JSON.stringify(record, null, 2);
  const tmpPath = `${lockPath}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;

  try {
    await writeFile(tmpPath, payload, { encoding: "utf8", flag: "wx" });
    try {
      await link(tmpPath, lockPath);
      return true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "EEXIST") return false;
      // Hard links aren't universally available (FAT/exFAT, some network
      // and container filesystems). Degrading to the non-atomic create is
      // strictly better than failing to lock at all, and readRecord()'s
      // re-read covers the window it reopens.
      return createLockFileNonAtomic(lockPath, payload);
    }
  } finally {
    // On success the hard link at lockPath keeps the content alive, so
    // dropping this second name is just tidy-up, not a deletion.
    await unlink(tmpPath).catch(() => {});
  }
}

async function createLockFileNonAtomic(lockPath: string, payload: string): Promise<boolean> {
  try {
    const handle = await open(lockPath, "wx");
    try {
      await handle.writeFile(payload, "utf8");
    } finally {
      await handle.close();
    }
    return true;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw err;
  }
}

/**
 * createdAt, not procStartTime: the latter is an opaque platform token
 * (clock ticks since boot, a FILETIME integer) that means nothing to a
 * human reading a refusal message. When the lock was taken is both
 * readable and the thing the user actually wants to know.
 */
function describeHolder(record: LockRecord): string {
  return `pid ${record.pid}, started ${record.createdAt}`;
}

/**
 * Held for the duration of one `palar live` invocation. Acquire once at
 * startup before any sandbox state is created; release in the same
 * unconditional teardown path as the sandbox itself.
 */
export class ScanLock {
  readonly path: string;
  readonly record: LockRecord;
  /** Set when acquiring had to break a crashed run's leftover lock, so the CLI can report it. */
  readonly reclaimed: string | null;

  private released = false;
  private exitHandler: (() => void) | null = null;
  private signalHandlers: [NodeJS.Signals, () => void][] = [];

  private constructor(path: string, record: LockRecord, reclaimed: string | null) {
    this.path = path;
    this.record = record;
    this.reclaimed = reclaimed;
  }

  static async acquire(opts: AcquireOptions = {}): Promise<ScanLock> {
    const dir = opts.stateDir ?? resolveStateDir();
    const probe = opts.probeProcess ?? probeProcessDefault;
    const lockPath = join(dir, LOCK_FILENAME);

    await mkdir(dir, { recursive: true });

    const self = await probe(process.pid);
    const record: LockRecord = {
      pid: process.pid,
      procStartTime: self.alive ? self.startedAt : null,
      createdAt: new Date().toISOString(),
      hostname: hostname(),
    };

    let reclaimed: string | null = null;

    for (let attempt = 0; attempt < MAX_ACQUIRE_ATTEMPTS; attempt++) {
      // Atomically publishes a fully-written lock file, or reports the name
      // as already taken. Never leaves a partially-written lock visible for
      // another acquirer to misread as corrupt — see createLockFile().
      if (await createLockFile(lockPath, record)) {
        return new ScanLock(lockPath, record, reclaimed);
      }

      const verdict = await classifyHolder(await readRecord(lockPath), probe);

      if (verdict.state === "live") {
        throw new ScanLockHeldError(
          `another palar live scan is running (${describeHolder(verdict.record)}). ` +
            "Live scans are serialized on this host because they install rules into " +
            "shared, host-global netfilter chains. Wait for it to finish, or stop it " +
            "and re-run.",
          verdict.record
        );
      }

      if (verdict.state === "foreign") {
        throw new ScanLockHeldError(
          `the live-scan lock at ${lockPath} was written by a different host ` +
            `(${verdict.record.hostname}, pid ${verdict.record.pid}), so this machine cannot ` +
            "tell whether that scan is still running. If it is not, delete the lock file " +
            "and re-run.",
          verdict.record
        );
      }

      reclaimed = verdict.reason;
      try {
        await unlink(lockPath);
      } catch (err) {
        // ENOENT means someone else broke the same stale lock first, which
        // is fine — the next iteration's O_EXCL create settles who wins.
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
      }
    }

    throw new Error(
      `could not acquire the live-scan lock at ${lockPath} after ${MAX_ACQUIRE_ATTEMPTS} attempts ` +
        "(it is being repeatedly created and broken by other processes)"
    );
  }

  /**
   * Registers best-effort release on the abrupt paths that skip `finally`:
   * process exit and the catchable termination signals. SIGKILL and a hard
   * power loss are deliberately not covered and cannot be — that is
   * precisely the case the stale-lock detection in classifyHolder() exists
   * to clean up on the next run.
   *
   * The exit handler must be synchronous (Node runs no further async work
   * after 'exit'), hence releaseSync().
   */
  installCrashHandlers(): void {
    this.exitHandler = () => this.releaseSync();
    process.on("exit", this.exitHandler);

    for (const signal of ["SIGINT", "SIGTERM", "SIGHUP", "SIGBREAK"] as NodeJS.Signals[]) {
      const handler = () => {
        this.releaseSync();
        // Re-raise with the default disposition so the exit status still
        // reflects the signal rather than a plain 0, and so anything else
        // listening on the same signal is not starved.
        process.exit(128 + (signalNumber(signal) ?? 0));
      };
      try {
        process.on(signal, handler);
        this.signalHandlers.push([signal, handler]);
      } catch {
        // SIGBREAK is Windows-only and SIGHUP is not universally
        // deliverable; failing to register one is not fatal.
      }
    }
  }

  private removeCrashHandlers(): void {
    if (this.exitHandler) {
      process.removeListener("exit", this.exitHandler);
      this.exitHandler = null;
    }
    for (const [signal, handler] of this.signalHandlers) {
      process.removeListener(signal, handler);
    }
    this.signalHandlers = [];
  }

  /**
   * Only ever removes a lock file that is still *ours*. If our lock was
   * broken as stale by another process (which then took its own), the file
   * on disk belongs to that scan and must survive our teardown — otherwise
   * releasing here would strip a live scan's lock and reintroduce the very
   * race this module closes.
   */
  private isStillOurs(raw: string): boolean {
    try {
      const onDisk = JSON.parse(raw) as LockRecord;
      return onDisk.pid === this.record.pid && onDisk.createdAt === this.record.createdAt;
    } catch {
      return false;
    }
  }

  /** False once release()/releaseSync() has run. */
  get held(): boolean {
    return !this.released;
  }

  /**
   * Runtime half of the "callers must hold the lock" contract that
   * sweepOrphanedSandboxState() enforces at the type level by demanding a
   * ScanLock. The type alone proves a lock object was *obtained*; this
   * proves it has not since been released, which is the property that
   * actually matters — a released lock is exactly as unsafe to sweep under
   * as no lock at all.
   */
  assertHeld(operation: string): void {
    if (this.released) {
      throw new Error(
        `${operation} requires the live-scan lock to still be held, but it has already ` +
          "been released. Sweeping without the lock can reclaim a concurrent scan's live " +
          "container and delete its egress firewall."
      );
    }
  }

  /** Idempotent and never throws — teardown must not turn into a scan failure. */
  async release(): Promise<void> {
    if (this.released) return;
    this.released = true;
    this.removeCrashHandlers();
    try {
      const raw = await readFile(this.path, "utf8");
      if (this.isStillOurs(raw)) await unlink(this.path);
    } catch {
      // Already gone, or unreadable — nothing safe or useful left to do.
    }
  }

  /** Synchronous counterpart for the 'exit' and signal paths. Same semantics. */
  releaseSync(): void {
    if (this.released) return;
    this.released = true;
    this.removeCrashHandlers();
    try {
      const raw = readFileSync(this.path, "utf8");
      if (this.isStillOurs(raw)) unlinkSync(this.path);
    } catch {
      // As above.
    }
  }
}

/** Exit-code convention only; Node does not expose signal numbers directly. */
function signalNumber(signal: NodeJS.Signals): number | undefined {
  return { SIGHUP: 1, SIGINT: 2, SIGTERM: 15, SIGBREAK: 21 }[signal as string];
}
