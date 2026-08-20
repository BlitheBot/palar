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
        mode: { type: "string", const: "readonly" },
      },
    },
  });
  assert.deepEqual(findings, []);
});

test("format does NOT suppress IV-001 — it annotates a shape, it does not narrow values", () => {
  // mcp-server-fetch's actual schema. `format: "uri"` excludes strings that
  // are not URIs, which is precisely not the dangerous set:
  // http://169.254.169.254/latest/meta-data/ is a perfectly valid URI.
  // Counting it as a constraint silenced both the finding and the probe.
  const findings = check({
    name: "fetch",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", format: "uri", minLength: 1, title: "Url" },
      },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["IV-001"]);
});

test("length bounds and documentation keywords do not suppress IV-001 either", () => {
  const findings = check({
    name: "deploy",
    inputSchema: {
      type: "object",
      properties: {
        command: {
          type: "string",
          minLength: 1,
          maxLength: 2048,
          title: "Command",
          description: "the command to run",
          default: "ls",
        },
      },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["IV-001"]);
});

test("unconstrained sensitive string produces IV-001 at medium, worded as a hypothesis", () => {
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
  // Not high. A field-name keyword cannot establish that a value reaches
  // an interpreter, and high asserts a confidence the method lacks.
  assert.equal(finding.severity, "medium");
  assert.match(finding.title, /unverified/i);
  assert.match(finding.detail, /hypothesis/i);
  // The remediation must not imply a schema constraint is definitely the
  // fix — for server-filesystem it would break the server.
  assert.match(finding.remediation!, /defence in depth|neither necessary nor possible/i);
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

test("a trivial catch-all pattern on a sensitive field fires IV-003", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string", pattern: "^.*$" } },
    },
  });
  // IV-003 owns the vacuous-pattern case; IV-001 steps aside so one field
  // never produces two findings that say the same thing.
  assert.deepEqual(findings.map((f) => f.ruleId), ["IV-003"]);
  assert.equal(findings[0]!.severity, "medium");
});

test("a trivial pattern alongside a format still fires only IV-003", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { url: { type: "string", pattern: ".*", format: "uri" } },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["IV-003"]);
});

test("const alone constrains a sensitive field", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { command: { type: "string", const: "status" } },
    },
  });
  assert.deepEqual(findings, []);
});

test("a genuinely constraining pattern fires neither IV-001 nor IV-003", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", pattern: "^/safe/[A-Za-z0-9._-]{1,64}$" },
      },
    },
  });
  assert.deepEqual(findings, []);
});

test("a trivial pattern on a non-sensitive field does not fire IV-003", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { notes: { type: "string", pattern: ".*" } },
    },
  });
  assert.deepEqual(findings, []);
});

test("catastrophic-backtracking shapes fire IV-004", () => {
  for (const pattern of ["^(a+)+$", "^([a-z]+)*$", "^(\\d+){2,}$", "foo.*.*bar", "^(x|x)+$"]) {
    const findings = check({
      name: "t",
      inputSchema: {
        type: "object",
        properties: { notes: { type: "string", pattern } },
      },
    });
    assert.deepEqual(
      findings.map((f) => f.ruleId),
      ["IV-004"],
      `expected IV-004 for pattern ${pattern}`
    );
  }
});

test("legitimate repetition does not false-positive IV-004", () => {
  for (const pattern of [
    "^[a-z]+(-[a-z]+)*$",
    "^[A-Za-z ,.-]{1,80}$",
    "^\\d{1,3}(\\.\\d{1,3}){3}$",
    "^https://[a-z0-9.-]+/[a-z0-9/_-]*$",
  ]) {
    const findings = check({
      name: "t",
      inputSchema: {
        type: "object",
        properties: { notes: { type: "string", pattern } },
      },
    });
    assert.deepEqual(findings, [], `unexpected finding for pattern ${pattern}`);
  }
});

function deepSchema(depth: number): Record<string, unknown> {
  let node: Record<string, unknown> = { type: "string" };
  for (let i = 0; i < depth; i++) {
    node = { type: "object", properties: { child: node } };
  }
  return node;
}

test("excessive nesting stops walking with a warning, not a stack overflow", () => {
  const warnings: string[] = [];
  const findings = inputValidationRule.check(
    {
      name: "deep",
      inputSchema: deepSchema(200),
    } as unknown as MCPToolDefinition,
    {
      file: "deep.json",
      config: {
        limits: { maxFileSize: 1, maxNestingDepth: 5, maxSchemaNodes: 5000 },
      },
      warn: (m) => warnings.push(m),
    }
  );
  assert.ok(Array.isArray(findings));
  assert.equal(warnings.length, 1);
  assert.ok(warnings[0]!.includes("nesting depth limit (5)"));
});

test("excessive node count stops walking with a warning", () => {
  const properties: Record<string, unknown> = {};
  for (let i = 0; i < 50; i++) properties[`p${i}`] = { type: "string" };
  const warnings: string[] = [];
  inputValidationRule.check(
    {
      name: "wide",
      inputSchema: { type: "object", properties },
    } as unknown as MCPToolDefinition,
    {
      file: "wide.json",
      config: {
        limits: { maxFileSize: 1, maxNestingDepth: 50, maxSchemaNodes: 10 },
      },
      warn: (m) => warnings.push(m),
    }
  );
  assert.equal(warnings.length, 1);
  assert.ok(warnings[0]!.includes("node limit (10)"));
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
