/**
 * Guards the boundary between palar's own setup and the scan `--timeout-ms`
 * bounds.
 *
 * Setup — Docker preflight, building the sandbox images, the network, the
 * oracle, the firewall — is deliberately NOT raced by the overall deadline.
 * On a first run it has to fetch a ~300MB base image, and racing that
 * against a scan budget reports palar's own installation as a target that
 * never answered.
 *
 * The regression this exists for is sharper than mis-attributed time. The
 * deadline used to be armed at the top of runLiveScan(), before setup, while
 * nothing awaited it until the Promise.race() at the bottom. A
 * `--timeout-ms` smaller than the setup duration therefore rejected a
 * promise with no handler attached: an unhandled rejection, which killed the
 * process outright (exit 1, a Node stack trace on stderr, no report) and
 * leaked the sandbox network setup had already created for the next run's
 * sweep to reclaim. A timer must not start before something is ready to
 * catch it.
 *
 * Docker is genuinely required here: the property under test is that setup
 * OUTLASTS the deadline, and without a daemon setup fails in milliseconds
 * and never reaches the interesting state.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runLiveScan } from "./liveScan.js";

const execFileAsync = promisify(execFile);

async function dockerIsAvailable(): Promise<boolean> {
  try {
    await execFileAsync("docker", ["version", "--format", "{{.Server.Version}}"]);
    return true;
  } catch {
    return false;
  }
}

const dockerAvailable = await dockerIsAvailable();

test(
  "an overall timeout shorter than setup does not crash, and does not abort setup",
  {
    skip: dockerAvailable ? false : "Docker backend not available; sandbox setup requires Docker",
    timeout: 120_000,
  },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "palar-setup-deadline-"));
    try {
      // A real file so the pre-flight passes and the scan proceeds to the
      // point where setup actually runs. It is not a working MCP server,
      // which is fine — the connect failing is not what is under test.
      await writeFile(join(dir, "server.js"), "process.stdin.resume();", "utf8");

      // 1ms: far below any possible sandbox setup. If the deadline were
      // armed before setup, this call would not return at all — the process
      // would die on an unhandled rejection and take the test runner with
      // it.
      const result = await runLiveScan(
        { name: "t", transport: "stdio", command: "node", args: ["server.js"] },
        [],
        { targetDir: dir, overallTimeoutMs: 1, connectTimeoutMs: 1_000 }
      );

      // Setup ran to completion despite the 1ms scan budget. That number
      // being larger than the budget IS the assertion.
      assert.ok(
        result.sandboxSetupMs > 1,
        `setup reported ${result.sandboxSetupMs}ms, which does not exceed the 1ms scan ` +
          `budget — this test cannot distinguish the two phases`
      );
      // The oracle really started, i.e. setup was not cut short.
      assert.notEqual(result.oracle.baseUrl, "");

      // And the deadline still applies to the scan, reported as the honest
      // outcome rather than as a crash.
      assert.equal(result.outcome, "never-reached");
      assert.notEqual(result.unreachable, null);
      assert.equal(result.probes.length, 0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
);

test(
  "a setup failure is reported as palar's own, not as the target's",
  {
    skip: dockerAvailable ? false : "Docker backend not available; sandbox setup requires Docker",
    timeout: 120_000,
  },
  async () => {
    const dir = await mkdtemp(join(tmpdir(), "palar-setup-deadline-"));
    try {
      await writeFile(join(dir, "server.js"), "process.stdin.resume();", "utf8");
      // An oracle host that cannot be bound fails during setup. SSE so no
      // container is involved and the failure is unambiguously setup's.
      const result = await runLiveScan(
        { name: "t", transport: "sse", url: "http://127.0.0.1:9/sse" },
        [],
        { targetDir: dir, oracleHost: "203.0.113.1", overallTimeoutMs: 5_000 }
      );

      assert.equal(result.outcome, "never-reached");
      // The distinction that matters: this says palar's setup failed, not
      // that the server did anything.
      assert.match(result.unreachable!.reason, /could not prepare its own sandbox/);
      assert.match(result.unreachable!.reason, /rather than anything about the server/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
);
