import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DEFAULT_CONFIG,
  loadConfigFile,
  resolveConfig,
} from "./config.js";
import { runAudit } from "./auditor.js";
import { inputValidationRule } from "../rules/input-validation.js";
import { textSanitizerRule } from "../rules/text-sanitizer.js";
import { networkBoundsRule } from "../rules/network-bounds.js";
import type { MCPToolDefinition, MCPServerConfig } from "./types.js";

test("no config resolves to exactly the built-in defaults", () => {
  assert.deepEqual(resolveConfig(undefined), DEFAULT_CONFIG);
  assert.deepEqual(resolveConfig({ configVersion: 1 }), DEFAULT_CONFIG);
});

test("sensitiveKeywords override changes input-validation behavior", () => {
  const config = resolveConfig({
    configVersion: 1,
    sensitiveKeywords: ["frobnicate"],
  });
  const tool = {
    name: "t",
    inputSchema: {
      type: "object",
      properties: {
        frobnicate: { type: "string" },
        command: { type: "string" },
      },
    },
  } as unknown as MCPToolDefinition;
  const findings = inputValidationRule.check(tool, { file: "f.json", config });
  assert.equal(findings.length, 1);
  assert.ok(findings[0]!.location.jsonPath?.endsWith("frobnicate"));
});

test("unicodeCategories override changes text-sanitizer behavior", () => {
  const config = resolveConfig({
    configVersion: 1,
    unicodeCategories: { zeroWidth: [] },
  });
  const tool = {
    name: "t",
    description: `a${String.fromCodePoint(0x200b)}b`,
  } as MCPToolDefinition;
  assert.deepEqual(textSanitizerRule.check(tool, { file: "f.json", config }), []);
  // Other categories keep their defaults.
  const bidi = {
    name: "t",
    description: `a${String.fromCodePoint(0x202e)}b`,
  } as MCPToolDefinition;
  assert.equal(textSanitizerRule.check(bidi, { file: "f.json", config }).length, 1);
});

test("network pattern override changes network-bounds behavior", () => {
  const config = resolveConfig({
    configVersion: 1,
    network: { loopbackHosts: [], loopbackPatterns: [] },
  });
  const server = {
    name: "s",
    network: {
      egressFilterEnabled: true,
      egressAllowlist: ["x"],
      exposedHosts: ["localhost"],
    },
  } as unknown as MCPServerConfig;
  assert.deepEqual(networkBoundsRule.check(server, { file: "f.json", config }), []);
});

test("severityOverrides are applied by the auditor and affect the score", () => {
  const discovered = {
    tools: [
      {
        file: "f.json",
        definition: {
          name: "t",
          description: "A normal deploy tool for services",
          inputSchema: {
            type: "object",
            properties: { command: { type: "string" } },
          },
        } as unknown as MCPToolDefinition,
      },
    ],
    servers: [],
    warnings: [],
  };
  const config = resolveConfig({
    configVersion: 1,
    severityOverrides: { "IV-001": "info" },
  });
  const result = runAudit(discovered, config);
  const iv = result.findings.find((f) => f.ruleId === "IV-001");
  assert.ok(iv);
  assert.equal(iv.severity, "info");
  assert.equal(result.score.value, 100);
});

test("malformed configs fail with clear errors", () => {
  assert.throws(() => resolveConfig({}), /configVersion/);
  assert.throws(() => resolveConfig({ configVersion: 2 }), /configVersion/);
  assert.throws(() => resolveConfig({ configVersion: 1, nope: true }), /unknown key/);
  assert.throws(
    () => resolveConfig({ configVersion: 1, sensitiveKeywords: [5] }),
    /sensitiveKeywords/
  );
  assert.throws(
    () => resolveConfig({ configVersion: 1, severityOverrides: { "IV-001": "fatal" } }),
    /severityOverrides/
  );
  assert.throws(
    () => resolveConfig({ configVersion: 1, unicodeCategories: { zeroWidth: ["xyz!"] } }),
    /hex code/
  );
  assert.throws(
    () => resolveConfig({ configVersion: 1, unicodeCategories: { madeUp: [] } }),
    /unknown category/
  );
  assert.throws(
    () => resolveConfig({ configVersion: 1, limits: { maxFileSize: -1 } }),
    /positive integer/
  );
  assert.throws(
    () => resolveConfig({ configVersion: 1, network: { loopbackPatterns: ["("] } }),
    /invalid regular expression/
  );
});

test("loadConfigFile auto-discovers .palarrc.json and errors on missing explicit path", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palar-config-"));
  try {
    // No file present: defaults.
    const none = await loadConfigFile(undefined, dir);
    assert.deepEqual(none, DEFAULT_CONFIG);
    // Auto-discovered file applies.
    await writeFile(
      join(dir, ".palarrc.json"),
      JSON.stringify({ configVersion: 1, limits: { maxNestingDepth: 7 } }),
      "utf8"
    );
    const found = await loadConfigFile(undefined, dir);
    assert.equal(found.limits.maxNestingDepth, 7);
    // Explicit missing path is an error, not a silent fallback.
    await assert.rejects(
      () => loadConfigFile(join(dir, "nope.json"), dir),
      /not found or unreadable/
    );
    // Malformed file is an error even when auto-discovered.
    await writeFile(join(dir, ".palarrc.json"), "{ nope", "utf8");
    await assert.rejects(() => loadConfigFile(undefined, dir), /malformed JSON/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
