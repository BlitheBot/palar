/**
 * End-to-end guards on what `palar scan` says when it examined nothing.
 *
 * These run the built binary the way a CI job would, because the bug they
 * exist to prevent is not visible from inside a unit: palar 0.2.0's
 * `scan --json` on a directory with no definitions printed
 * `"score": {"value": 100, "grade": "A"}` and exited 0. Every assertion
 * below is really the same assertion — palar must not publish a grade for
 * something it never looked at — checked once per way of looking at
 * nothing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// dist/cli/ -> package root
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(PACKAGE_ROOT, "dist", "cli", "index.js");

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): Promise<Run> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, ...args],
      { env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" } },
      (err, stdout, stderr) => {
        resolve({
          code: err ? ((err as NodeJS.ErrnoException & { code?: number }).code ?? 1) : 0,
          stdout,
          stderr,
        });
      }
    );
  });
}

async function emptyDir(): Promise<string> {
  return mkdtemp(join(tmpdir(), "palar-empty-scan-"));
}

test("scan --json on an empty directory reports no score, not a perfect one", async () => {
  const dir = await emptyDir();
  try {
    const { code, stdout, stderr } = await runCli(["scan", dir, "--json"]);

    const doc = JSON.parse(stdout) as Record<string, unknown>;
    assert.equal(doc.outcome, "nothing-discovered");
    assert.equal(
      "score" in doc,
      false,
      `scan --json published a score for a directory with nothing in it: ${stdout}`
    );
    assert.equal("findings" in doc, false);
    assert.deepEqual(doc.searched, [dir]);
    // Unchanged contract: an empty scan is not a failure unless the caller
    // asked for it to be with --fail-on-empty.
    assert.equal(code, 0);
    assert.match(stderr, /No MCP tool or server definition files found/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan --json --fail-on-empty on an empty directory exits 1, still with no score", async () => {
  const dir = await emptyDir();
  try {
    const { code, stdout } = await runCli(["scan", dir, "--json", "--fail-on-empty"]);
    const doc = JSON.parse(stdout) as Record<string, unknown>;
    assert.equal(doc.outcome, "nothing-discovered");
    assert.equal("score" in doc, false);
    assert.equal(code, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan (human output) on an empty directory prints no score line", async () => {
  const dir = await emptyDir();
  try {
    const { code, stdout } = await runCli(["scan", dir]);
    assert.doesNotMatch(stdout, /score \d+\/100/);
    assert.doesNotMatch(stdout, /grade A/);
    assert.equal(code, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan --from-command refuses a registry-fetch invocation with exit 2 and no score", async () => {
  // Never-reached: palar knows nothing about this target. Distinct from
  // exit 1 (reached, zero tools), which is a statement about the target.
  // Refused at plan time, so this test needs no Docker daemon.
  const { code, stdout, stderr } = await runCli([
    "scan",
    "--json",
    "--from-command",
    "npx",
    // After `--`, so the `-y` reaches the planner instead of being parsed
    // as an unknown palar option.
    "--",
    "-y",
    "@scope/definitely-not-installed",
  ]);

  const doc = JSON.parse(stdout) as Record<string, unknown>;
  assert.equal(doc.outcome, "never-reached");
  assert.equal("score" in doc, false);
  assert.match(String(doc.error), /already have installed/);
  assert.equal(code, 2);
  assert.match(stderr, /No score is reported/);
});

test("scan rejects --from-command combined with paths or --dir", async () => {
  const withPath = await runCli(["scan", ".", "--from-command", "node", "x.js"]);
  assert.notEqual(withPath.code, 0);
  assert.match(withPath.stderr, /cannot be combined with paths/);

  const withDir = await runCli(["scan", "--dir", ".", "--from-command", "node", "x.js"]);
  assert.notEqual(withDir.code, 0);
  assert.match(withDir.stderr, /cannot be used with option/);
});

test("scan rejects --from-url combined with --from-command", async () => {
  const { code, stderr } = await runCli([
    "scan",
    "--from-url",
    "http://127.0.0.1:45999/sse",
    "--from-command",
    "node",
    "x.js",
  ]);
  assert.notEqual(code, 0);
  assert.match(stderr, /cannot be used with option/);
});

test("scan --from-url on a dead endpoint is never-reached, exit 2, no score", async () => {
  // A port with nothing on it: the connection is refused immediately, so
  // this stays fast and needs no fixture server.
  const { code, stdout } = await runCli([
    "scan",
    "--json",
    "--from-url",
    "http://127.0.0.1:45999/sse",
    "--connect-timeout-ms",
    "3000",
    "--timeout-ms",
    "8000",
  ]);

  const doc = JSON.parse(stdout) as Record<string, unknown>;
  assert.equal(doc.outcome, "never-reached");
  assert.equal("score" in doc, false);
  assert.equal(doc.source, "<live http://127.0.0.1:45999/sse>");
  assert.equal(code, 2);
});

test("arguments after `--` are appended to --from-command's command line", async () => {
  // A target's own flags would otherwise be eaten by commander as unknown
  // palar options, which is what `--headless` does to a real playwright
  // server. The plan error echoes the full argv, so it doubles as proof the
  // passthrough tokens arrived.
  const { code, stdout } = await runCli([
    "scan",
    "--json",
    "--from-command",
    "node",
    "definitely-not-here.js",
    "--",
    "--headless",
    "--isolated",
  ]);

  const doc = JSON.parse(stdout) as Record<string, unknown>;
  assert.equal(doc.outcome, "never-reached");
  assert.match(String(doc.error), /node definitely-not-here\.js --headless --isolated/);
  assert.equal(code, 2);
});

test("a bare `--` without --from-command still scans the paths after it", async () => {
  // `--` keeps its ordinary meaning for a file-based scan. Reinterpreting it
  // unconditionally silently dropped the path and reported "nothing
  // discovered" for a directory the user had named.
  const dir = await emptyDir();
  try {
    const { stdout } = await runCli(["scan", "--json", "--", dir]);
    const doc = JSON.parse(stdout) as Record<string, unknown>;
    assert.deepEqual(doc.searched, [dir]);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("--from-env without --from-command is rejected rather than ignored", async () => {
  const { code, stderr } = await runCli(["scan", ".", "--from-env", "HOME=/tmp"]);
  assert.notEqual(code, 0);
  assert.match(stderr, /no --from-command here/);
});

test("--from-env rejects a bare name rather than inheriting it", async () => {
  // `--from-env HOME` most plausibly means "pass mine through", which is the
  // one thing this must never do.
  const { code, stderr } = await runCli([
    "scan",
    "--from-command",
    "node",
    "x.js",
    "--from-env",
    "HOME",
  ]);
  assert.notEqual(code, 0);
  assert.match(stderr, /expects KEY=VALUE/);
});
