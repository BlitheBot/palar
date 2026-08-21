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

// ---------------------------------------------------------------------------
// Acknowledgements.
//
// Validated harder than any other config key, because this is the one that
// decides which findings stop failing a build. A malformed entry must
// never degrade into a permissive one.
// ---------------------------------------------------------------------------

function ackConfig(entry: unknown): unknown {
  return { configVersion: 1, acknowledgements: [entry] };
}

const VALID_ACK = {
  ruleId: "IV-001",
  jsonPath: 'tools["start_process"].inputSchema.properties.command',
  reason: "shell tool; execution is the product",
  added: "2026-08-01",
};

test("a valid acknowledgement resolves", () => {
  const config = resolveConfig(ackConfig(VALID_ACK));
  assert.equal(config.acknowledgements.length, 1);
  assert.equal(config.acknowledgements[0]!.ruleId, "IV-001");
});

test("acknowledgements default to empty", () => {
  assert.deepEqual(resolveConfig({ configVersion: 1 }).acknowledgements, []);
});

test("a missing reason is rejected rather than defaulted", () => {
  // The reason IS the feature. An acknowledgement without one is a
  // suppression with extra steps.
  const { reason, ...noReason } = VALID_ACK;
  assert.throws(() => resolveConfig(ackConfig(noReason)), /reason.*required/);
});

test("a missing added date is rejected", () => {
  const { added, ...noAdded } = VALID_ACK;
  assert.throws(() => resolveConfig(ackConfig(noAdded)), /added.*required/);
});

test("a non-date added is rejected", () => {
  assert.throws(
    () => resolveConfig(ackConfig({ ...VALID_ACK, added: "last tuesday" })),
    /real calendar date/
  );
});

test("an impossible calendar date is rejected", () => {
  // Date() would roll 2026-02-31 into March rather than failing.
  assert.throws(
    () => resolveConfig(ackConfig({ ...VALID_ACK, added: "2026-02-31" })),
    /real calendar date/
  );
});

test("an unknown key in an acknowledgement is rejected", () => {
  assert.throws(
    () => resolveConfig(ackConfig({ ...VALID_ACK, severity: "low" })),
    /unknown key "severity"/
  );
});

test("acceptsConfirmed without expires is rejected", () => {
  assert.throws(
    () => resolveConfig(ackConfig({ ...VALID_ACK, acceptsConfirmed: true })),
    /"expires" is required/
  );
});

test("acceptsConfirmed with a distant expiry is rejected", () => {
  // Otherwise "expiry required" is satisfied by writing 2099-01-01, which
  // is no expiry wearing a costume.
  assert.throws(
    () =>
      resolveConfig(
        ackConfig({ ...VALID_ACK, acceptsConfirmed: true, expires: "2099-01-01" })
      ),
    /exceeds the 366-day maximum/
  );
});

test("acceptsConfirmed with a reasonable expiry is accepted", () => {
  const config = resolveConfig(
    ackConfig({ ...VALID_ACK, acceptsConfirmed: true, expires: "2027-01-01" })
  );
  assert.equal(config.acknowledgements[0]!.acceptsConfirmed, true);
  assert.equal(config.acknowledgements[0]!.expires, "2027-01-01");
});

test("an expiry before the added date is rejected", () => {
  assert.throws(
    () => resolveConfig(ackConfig({ ...VALID_ACK, expires: "2026-07-01" })),
    /before "added"/
  );
});

test("acknowledgements must be an array", () => {
  assert.throws(
    () => resolveConfig({ configVersion: 1, acknowledgements: {} }),
    /must be an array/
  );
});
