/**
 * Integration test for TA-101 against fixtures/contradiction-server.
 *
 * WHY A SECOND LIVE FIXTURE EXISTS. Nothing in the six-target sample
 * declares an annotation that a probe disproves, so TA-101's per-kind table
 * would otherwise ship on unit tests over hand-built structs alone — never
 * once having read a claim off a real `listTools()` response or matched it
 * to a callback that actually arrived. This test closes that gap end to
 * end: a real MCP server, in the sandbox, whose tools claim to be safe
 * while reaching a shell and fetching an attacker-supplied URL.
 *
 * WHAT IT GUARDS, beyond "the rule fires". Half the assertions below are
 * controls, because the way this rule fails is by becoming eager rather
 * than by going quiet. `load_reference` declares `readOnlyHint: true` and
 * is genuinely exploitable, and must still not be reported for that hint;
 * `run_task` confirms an injection while declaring nothing at all. A
 * version of TA-101 that substituted the spec's defaults for absent
 * declarations, or that treated a callback as evidence about every
 * related-sounding hint, passes the positive assertions and fails these.
 *
 * Requires a Docker backend (stdio targets run in the sandbox container),
 * and the fixture's own node_modules — see its README. When Docker is
 * unavailable the test is skipped rather than failed, matching how
 * `palar live` itself refuses to run unsandboxed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runLiveScan } from "./liveScan.js";
import { annotationContradictionFindings } from "./annotation-contradiction.js";
import { escalateConfirmedFindings } from "./escalate.js";
import { computeScore } from "../core/compliance.js";
import type { AuditResult, MCPServerConfig } from "../core/types.js";

const execFileAsync = promisify(execFile);

// dist/live/ -> repo root; the fixture (with its own node_modules) lives in
// the source tree, not under dist.
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..");
const FIXTURE_DIR = join(REPO_ROOT, "fixtures", "contradiction-server");

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
  "TA-101 fires on contradicted claims and stays silent on every control",
  {
    skip: dockerAvailable ? false : "Docker backend not available; live scan requires Docker",
    timeout: 180_000,
  },
  async () => {
    const server: MCPServerConfig = {
      name: "contradiction-server",
      transport: "stdio",
      command: "node",
      args: ["src/index.js"],
    };

    const result = await runLiveScan(server, [], {
      targetDir: FIXTURE_DIR,
      connectTimeoutMs: 30_000,
      overallTimeoutMs: 120_000,
      callbackTimeoutMs: 8_000,
    });

    assert.deepEqual(result.errors, [], `live scan reported errors: ${result.errors.join("; ")}`);

    // ---- the passthrough, proven over a real MCP connection ----
    // Not a restatement of enumerate.ts's unit tests: this is the SDK's own
    // listTools() response on the wire, which is the thing those tests
    // model.
    const byName = new Map(result.liveTools.map((t) => [t.name, t]));
    assert.equal(
      byName.get("probe_host")?.title,
      "Check host reachability",
      "the top-level title position did not survive listTools()"
    );
    assert.match(
      byName.get("load_reference")?.annotations?.title ?? "",
      /^Load reference document/,
      "the annotations.title position did not survive listTools()"
    );
    assert.equal(byName.get("probe_host")?.annotations?.readOnlyHint, true);
    assert.equal(byName.get("load_reference")?.annotations?.openWorldHint, false);
    assert.equal(
      byName.get("run_task")?.annotations,
      undefined,
      "run_task declares no annotations and must not acquire any"
    );

    // ---- each probe class confirms independently ----
    // Separate assertions, not an OR, for the reason vuln-server's test
    // states: neither class may stand in for the other.
    const confirmed = (tool: string, field: string, kind: string): boolean =>
      result.probes.some(
        (p) => p.toolName === tool && p.fieldPath === field && p.kind === kind && p.status === "confirmed"
      );
    const probeSummary = JSON.stringify(
      result.probes.map((p) => ({ tool: p.toolName, field: p.fieldPath, status: p.status }))
    );

    assert.ok(
      confirmed("probe_host", "hostname", "command-injection"),
      `command-injection did NOT confirm on probe_host.hostname — probes: ${probeSummary}`
    );
    assert.ok(
      confirmed("load_reference", "url", "ssrf"),
      `ssrf did NOT confirm on load_reference.url — probes: ${probeSummary}`
    );
    assert.ok(
      confirmed("run_task", "command", "command-injection"),
      `command-injection did NOT confirm on run_task.command — probes: ${probeSummary}`
    );

    // ---- the contradictions themselves ----
    const findings = annotationContradictionFindings(result, "<live server>");
    const byTool = new Map(
      findings.map((f) => [/^Tool "([^"]+)"/.exec(f.title)?.[1] ?? "", f])
    );

    assert.deepEqual(
      [...byTool.keys()].sort(),
      ["load_reference", "probe_host"],
      "exactly two tools should carry a contradiction"
    );

    const host = byTool.get("probe_host")!;
    assert.equal(host.ruleId, "TA-101");
    assert.equal(host.severity, "high");
    assert.equal(host.confidence, "confirmed");
    assert.match(host.detail, /readOnlyHint: true/);
    assert.match(host.detail, /openWorldHint: false/);
    // CONTROL: idempotentHint IS declared true and is not in the
    // command-injection row. It appears in the declared-surface sentence and
    // never as a refuted claim.
    assert.match(host.detail, /idempotentHint: true/);
    assert.doesNotMatch(
      host.detail,
      /idempotentHint: true` — the tool/,
      "idempotentHint was reported as contradicted; the per-kind table has widened"
    );
    // CONTROL: destructiveHint was never declared, so it renders as
    // undeclared rather than as its spec default of true.
    assert.match(host.detail, /destructiveHint: not declared/);

    const ref = byTool.get("load_reference")!;
    assert.match(ref.detail, /openWorldHint: false/);
    // CONTROL, the sharpest one. readOnlyHint: true is declared here and the
    // tool really is exploitable — but an SSRF callback is not evidence that
    // the server's own environment changed. If this fails, TA-101 has begun
    // inferring instead of reporting.
    assert.doesNotMatch(
      ref.detail,
      /readOnlyHint: true` — the tool/,
      "an SSRF callback was treated as evidence about readOnlyHint"
    );

    // CONTROL: run_task confirms an injection and declares nothing. Its
    // absence above proves TA-101 is silent because no claim was made, not
    // because no callback arrived.
    assert.equal(byTool.has("run_task"), false);

    // ---- and it reaches the scored result, not just the renderer ----
    const empty: AuditResult = {
      timestamp: result.timestamp,
      toolsScanned: 0,
      serversScanned: 1,
      findings: [],
      score: computeScore([]),
      warnings: [],
    };
    const escalated = escalateConfirmedFindings(empty, [result]);
    assert.equal(
      escalated.findings.filter((f) => f.ruleId === "TA-101").length,
      2,
      "TA-101 findings did not survive into the escalated AuditResult"
    );
    assert.equal(escalated.score.grade, "F");
  }
);
