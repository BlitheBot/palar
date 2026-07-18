import { test } from "node:test";
import assert from "node:assert/strict";
import { inputValidationRule } from "./input-validation.js";
import type { MCPToolDefinition } from "../core/types.js";

const ctx = { file: "test.json" };
const check = (tool: unknown) =>
  inputValidationRule.check(tool as MCPToolDefinition, ctx);

test("constrained sensitive fields produce no finding", () => {
  const findings = check({
    name: "deploy",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", enum: ["build", "release"] },
        path: { type: "string", pattern: "^/safe/" },
        url: { type: "string", format: "uri" },
      },
    },
  });
  assert.deepEqual(findings, []);
});

test("unconstrained sensitive string produces IV-001", () => {
  const findings = check({
    name: "deploy",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string" } },
    },
  });
  assert.equal(findings.length, 1);
  const finding = findings[0]!;
  assert.equal(finding.ruleId, "IV-001");
  assert.equal(finding.severity, "high");
  assert.ok(finding.location.jsonPath?.endsWith("properties.command"));
});

test("non-sensitive unconstrained string produces no finding", () => {
  const findings = check({
    name: "deploy",
    inputSchema: {
      type: "object",
      properties: { message: { type: "string" } },
    },
  });
  assert.deepEqual(findings, []);
});

test("sensitive-named tool with no inputSchema produces IV-002", () => {
  const findings = check({ name: "run_shell" });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, "IV-002");
  assert.equal(findings[0]!.severity, "low");
});

test("non-sensitive tool with no inputSchema produces nothing", () => {
  assert.deepEqual(check({ name: "get_weather" }), []);
});

test("nested arrays of arrays are walked to the sensitive field", () => {
  const findings = check({
    name: "batcher",
    inputSchema: {
      type: "object",
      properties: {
        batches: {
          type: "array",
          items: {
            type: "array",
            items: {
              type: "object",
              properties: { command: { type: "string" } },
            },
          },
        },
      },
    },
  });
  assert.equal(findings.length, 1);
  assert.ok(
    findings[0]!.location.jsonPath?.includes("batches[][].command"),
    `unexpected path: ${findings[0]!.location.jsonPath}`
  );
});

test("null and scalar schema nodes do not throw", () => {
  const findings = check({
    name: "weird",
    inputSchema: {
      type: "object",
      properties: {
        broken: null,
        alsoBroken: 5,
        command: { type: "string" },
      },
    },
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, "IV-001");
});
