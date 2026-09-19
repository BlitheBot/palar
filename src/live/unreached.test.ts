/**
 * Guards on what `palar live` says about a target it never reached.
 *
 * The bug these exist to prevent: pointed at mcp-server-fetch (declared
 * `python -m mcp_server_fetch`), palar started a container, handed the
 * literal string "python" to Node as a script path, died with
 * `Cannot find module '/target/python'` — and then emitted a report and a
 * score of 85/B and exited 0. Every assertion below is the same assertion
 * checked once per surface: a live run that examined nothing must not be
 * reportable as one that examined something and found it clean.
 *
 * runLiveScan()'s pre-flight is unit-testable without Docker precisely
 * because it happens before any sandbox exists — that ordering is the point
 * of the check, so a test that needed a daemon would be testing the wrong
 * thing.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runLiveScan } from "./liveScan.js";
import { renderLiveMarkdownReport } from "./report.js";
import { findProgramToken } from "./enumerate.js";
import type { AuditResult } from "../core/types.js";

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

const STATIC: AuditResult = {
  timestamp: "2026-08-20T00:00:00.000Z",
  toolsScanned: 1,
  serversScanned: 1,
  findings: [
    {
      ruleId: "IV-001",
      pillar: "schema-integrity",
      severity: "medium",
      confidence: "hypothesized",
      title: "Unconstrained input on potentially sensitive field \"url\" (unverified)",
      detail: "hypothesis",
      location: { file: "mcp.tools.json", jsonPath: 'tools["fetch"].inputSchema.properties.url' },
    },
  ],
  score: { value: 85, grade: "B" },
  warnings: [],
};

test("a stdio target whose command names no file on disk is never-reached, not probed", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palar-unreached-"));
  try {
    const result = await runLiveScan(
      { name: "mcp-server-fetch", transport: "stdio", command: "python", args: ["-m", "mcp_server_fetch"] },
      [],
      { targetDir: dir }
    );

    assert.equal(result.outcome, "never-reached");
    assert.notEqual(result.unreachable, null);
    // The reason has to name what was declared and why it cannot run — the
    // whole failure was that "Cannot find module '/target/python'" told the
    // reader nothing they could act on.
    assert.match(result.unreachable!.reason, /python -m mcp_server_fetch/);
    assert.match(result.unreachable!.reason, /Node runtime/);
    assert.equal(result.probes.length, 0);
    assert.equal(result.liveTools.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the pre-flight refuses before any container or oracle exists", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palar-unreached-"));
  try {
    const started = Date.now();
    const result = await runLiveScan(
      { name: "t", transport: "stdio", command: "uvx", args: ["some-server"] },
      [],
      { targetDir: dir }
    );
    // No sandbox was created, so no oracle was ever bound. That is the
    // observable proof the check ran early rather than after a Docker build.
    assert.equal(result.oracle.baseUrl, "");
    assert.equal(result.pid, null);
    assert.ok(
      Date.now() - started < 5_000,
      "the pre-flight took long enough to have started a container"
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the pre-flight does not over-refuse a command that DOES name a real file", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palar-unreached-"));
  try {
    await writeFile(join(dir, "server.js"), "// an MCP server would live here", "utf8");
    // Asserted at the check itself rather than by running a scan: getting
    // past the pre-flight means starting a container, and a test that needs
    // a Docker daemon to prove a filesystem check would be testing the
    // wrong thing (and would not run in CI without one).
    assert.equal(findProgramToken(["node", "server.js"], dir), "server.js");
    assert.equal(findProgramToken(["node", "./server.js"], dir), "./server.js");
    // Flags are never mistaken for the program, even when a file of that
    // name happens to sit in the mount.
    await writeFile(join(dir, "--headless"), "", "utf8");
    assert.equal(findProgramToken(["--headless", "server.js"], dir), "server.js");
    // And the refusing case, from the same function the scan uses.
    assert.equal(findProgramToken(["python", "-m", "mcp_server_fetch"], dir), undefined);
    assert.equal(findProgramToken(["npx", "-y", "@scope/server"], dir), undefined);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("the never-reached report does not have the shape of a clean pass", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palar-unreached-"));
  try {
    const result = await runLiveScan(
      { name: "mcp-server-fetch", transport: "stdio", command: "python", args: ["-m", "x"] },
      [],
      { targetDir: dir }
    );
    const report = renderLiveMarkdownReport(STATIC, result);

    assert.match(report, /NEVER REACHED/);
    assert.match(report, /examined nothing here, which is not the same as finding nothing/);
    // The empty-section shape is the danger: a page of "CONFIRMED: None."
    // reads as a target that was exercised and came back clean.
    assert.doesNotMatch(report, /## CONFIRMED/);
    assert.doesNotMatch(report, /## ATTEMPTED/);
    assert.doesNotMatch(report, /## STATIC-ONLY/);
    // And no grade for a server that never answered.
    assert.doesNotMatch(report, /grade [A-F]/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a non-Node runtime is refused at pre-flight even when its script exists on disk", async () => {
  // The gap this closes: `python3 ./server.py` passes findProgramToken()
  // because server.py is real, so live used to start a container and die in
  // it as `Cannot find module '/target/python3'` about 30s later.
  const dir = await mkdtemp(join(tmpdir(), "palar-unreached-"));
  try {
    await writeFile(join(dir, "server.py"), "import sys\n", "utf8");
    const started = Date.now();
    const result = await runLiveScan(
      { name: "py", transport: "stdio", command: "python3", args: ["./server.py"] },
      [],
      { targetDir: dir }
    );

    assert.equal(result.outcome, "never-reached");
    assert.match(result.unreachable!.reason, /python3 \.\/server\.py/);
    assert.match(result.unreachable!.reason, /a Python server/);
    assert.match(result.unreachable!.reason, /scan --from-url/);
    // Refused before the sandbox: no oracle bound, no process, no Docker time.
    assert.equal(result.oracle.baseUrl, "");
    assert.equal(result.pid, null);
    assert.equal(result.sandboxSetupMs, 0);
    assert.ok(Date.now() - started < 5_000, "the refusal took long enough to have started a container");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test(
  "control: a Node target still gets past the runtime gate and runs in the container",
  {
    skip: dockerAvailable ? false : "Docker backend not available; this control needs a container",
    timeout: 180_000,
  },
  async () => {
    // Without this, a gate that refused everything would pass the test above.
    // The marker can only reach the reason if Node executed server.js inside
    // the sandbox and its stderr came back, so it proves the whole path.
    const dir = await mkdtemp(join(tmpdir(), "palar-unreached-"));
    try {
      // mkdtemp creates the directory 0700, owned by the host user. The
      // sandbox runs as root with --cap-drop=ALL, so it has no
      // CAP_DAC_OVERRIDE and is bound by ordinary permission bits: on a
      // native Linux Engine (CI) it cannot enter a 0700 directory owned by
      // another uid, and Node reports that as "Cannot find module
      // '/target/server.js'". Docker Desktop's bind mounts don't enforce
      // host modes, which is why this passed locally. 0755 is what a real
      // server checkout has, and what the fixture directories have.
      await chmod(dir, 0o755);
      await writeFile(
        join(dir, "server.js"),
        'console.error("PALAR_CONTROL_RAN"); process.exit(1);\n',
        "utf8"
      );
      const result = await runLiveScan(
        { name: "node-control", transport: "stdio", command: "node", args: ["./server.js"] },
        [],
        { targetDir: dir, connectTimeoutMs: 30_000, overallTimeoutMs: 120_000 }
      );

      assert.notEqual(result.oracle.baseUrl, "", "no oracle was bound, so the sandbox never came up");
      assert.match(result.unreachable?.reason ?? "", /PALAR_CONTROL_RAN/);
      assert.doesNotMatch(result.unreachable?.reason ?? "", /refuses to start it/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }
);

test("a server declaring no command at all is never-reached rather than throwing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palar-unreached-"));
  try {
    const result = await runLiveScan({ name: "t", transport: "stdio" }, [], { targetDir: dir });
    assert.equal(result.outcome, "never-reached");
    assert.match(result.unreachable!.reason, /declares no "command"/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
