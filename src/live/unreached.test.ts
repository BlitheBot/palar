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
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runLiveScan } from "./liveScan.js";
import { renderLiveMarkdownReport } from "./report.js";
import { findProgramToken } from "./enumerate.js";
import type { AuditResult } from "../core/types.js";

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
