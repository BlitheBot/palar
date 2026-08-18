/**
 * Integration test for the live scan against fixtures/vuln-server.
 *
 * THE MASKING BUG this guards against: the CLI fails the run (exit 1) if
 * *any* probe confirms. On the vuln-server fixture SSRF confirmed and made
 * the run exit nonzero, so the run "passed" while command-injection was
 * silently returning UNCONFIRMED. A test that only checked "the run found
 * something" (exit code, or `probes.some(confirmed)`) could never catch a
 * regression in one class as long as the other still fired.
 *
 * The fix is structural: assert EACH probe class confirms INDEPENDENTLY.
 * A future regression in command-injection can no longer hide behind SSRF,
 * and vice versa.
 *
 * Requires a Docker backend (stdio targets run in the sandbox container).
 * When Docker is unavailable the test is skipped rather than failed, matching
 * how `palar live` itself refuses to run unsandboxed.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { runLiveScan } from "./liveScan.js";
import type { MCPServerConfig } from "../core/types.js";

const execFileAsync = promisify(execFile);

// dist/live/ -> repo root; the fixture (with its own node_modules) lives in
// the source tree, not under dist.
const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, "..", "..");
const FIXTURE_DIR = join(REPO_ROOT, "fixtures", "vuln-server");

async function dockerIsAvailable(): Promise<boolean> {
  try {
    await execFileAsync("docker", ["version", "--format", "{{.Server.Version}}"]);
    return true;
  } catch {
    return false;
  }
}

const dockerAvailable = await dockerIsAvailable();

function probeSummary(probes: { toolName: string; fieldPath: string; kind: string; status: string }[]): string {
  return JSON.stringify(
    probes.map((p) => ({ tool: p.toolName, field: p.fieldPath, kind: p.kind, status: p.status }))
  );
}

test(
  "each probe class confirms INDEPENDENTLY against fixtures/vuln-server",
  {
    skip: dockerAvailable ? false : "Docker backend not available; live scan requires Docker",
    // Cold container + tsx compiling TypeScript before the MCP handshake was
    // measured at ~8-10s connect; give the whole scan generous headroom.
    timeout: 180_000,
  },
  async () => {
    const server: MCPServerConfig = {
      name: "vuln-server",
      transport: "stdio",
      command: "node",
      args: ["--import", "tsx", "src/index.ts"],
    };

    const result = await runLiveScan(server, [], {
      targetDir: FIXTURE_DIR,
      connectTimeoutMs: 30_000,
      overallTimeoutMs: 120_000,
      callbackTimeoutMs: 8_000,
    });

    assert.deepEqual(
      result.errors,
      [],
      `live scan reported errors: ${result.errors.join("; ")}`
    );

    const confirmed = (kind: string, tool: string, field: string): boolean =>
      result.probes.some(
        (p) =>
          p.kind === kind &&
          p.toolName === tool &&
          p.fieldPath === field &&
          p.status === "confirmed"
      );

    // Per-class assertion #1: command injection. This is the class the
    // masking bug let rot — assert it on its own.
    assert.ok(
      confirmed("command-injection", "run_diagnostic", "hostname"),
      "command-injection did NOT confirm on run_diagnostic.hostname — " +
        `probes: ${probeSummary(result.probes)}`
    );

    // Per-class assertion #2: SSRF. Deliberately a separate assertion, not
    // an OR with the one above, so neither class can stand in for the other.
    assert.ok(
      confirmed("ssrf", "fetch_url", "url"),
      "ssrf did NOT confirm on fetch_url.url — " +
        `probes: ${probeSummary(result.probes)}`
    );
  }
);
