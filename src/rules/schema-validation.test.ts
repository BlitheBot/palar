import { test } from "node:test";
import assert from "node:assert/strict";
import { schemaValidationRule } from "./schema-validation.js";
import type { MCPToolDefinition } from "../core/types.js";

const ctx = { file: "test.json" };
const check = (tool: unknown) =>
  schemaValidationRule.check(tool as MCPToolDefinition, ctx);
const ruleIds = (tool: unknown) => check(tool).map((f) => f.ruleId);

test("a well-formed schema produces zero findings", () => {
  const findings = check({
    name: "clean",
    inputSchema: {
      type: "object",
      properties: {
        city: { type: "string", pattern: "^[A-Za-z ]+$" },
        tags: { type: "array", items: { type: "string", enum: ["a", "b"] } },
        opts: {
          type: "object",
          properties: { verbose: { type: "boolean" } },
          required: ["verbose"],
        },
      },
      required: ["city"],
    },
  });
  assert.deepEqual(findings, []);
});

test("missing inputSchema produces zero findings", () => {
  assert.deepEqual(check({ name: "bare" }), []);
});

test("an invalid type value fires SV-001 at high severity", () => {
  const findings = check({
    name: "typo",
    inputSchema: {
      type: "object",
      properties: { city: { type: "sting" } },
    },
  });
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.ruleId, "SV-001");
  assert.equal(findings[0]!.severity, "high");
  assert.ok(findings[0]!.location.jsonPath?.endsWith("properties.city"));
});

test("properties on a non-object node fires SV-002", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: {
        oops: { type: "string", properties: { x: { type: "string" } } },
      },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["SV-002"]);
  assert.equal(findings[0]!.severity, "medium");
});

test("properties with a missing type fires SV-002 (including at the root)", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: { properties: { x: { type: "string" } } },
    }),
    ["SV-002"]
  );
});

test("items on a non-array node fires SV-003", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { oops: { type: "string", items: { type: "string" } } },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["SV-003"]);
  assert.equal(findings[0]!.severity, "medium");
});

test("required listing undeclared properties fires SV-004", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { present: { type: "string" } },
      required: ["present", "ghost"],
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["SV-004"]);
  assert.equal(findings[0]!.severity, "medium");
  assert.ok(findings[0]!.detail.includes('"ghost"'));
  assert.ok(!findings[0]!.detail.includes('"present",'));
});

test("required with no properties at all fires SV-004", () => {
  assert.deepEqual(
    ruleIds({ name: "t", inputSchema: { type: "object", required: ["x"] } }),
    ["SV-004"]
  );
});

test("a $ref cycle back to the root fires SV-005 at high severity", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { self: { $ref: "#" } },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["SV-005"]);
  assert.equal(findings[0]!.severity, "high");
});

test("a $ref cycle to a mid-tree ancestor fires SV-005", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: {
          branch: {
            type: "object",
            properties: { loop: { $ref: "#/properties/branch" } },
          },
        },
      },
    }),
    ["SV-005"]
  );
});

test("a non-cyclic local $ref produces no finding", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: {
          a: { type: "string", enum: ["x"] },
          b: { $ref: "#/properties/a" },
        },
      },
    }),
    []
  );
});

test("an unresolvable or external $ref is skipped", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: {
          a: { $ref: "#/definitions/missing" },
          b: { $ref: "https://example.com/schema.json#" },
        },
      },
    }),
    []
  );
});

test("checks apply to deeply nested nodes through arrays", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: {
        rows: {
          type: "array",
          items: {
            type: "array",
            items: { type: "objct", properties: { x: { type: "string" } } },
          },
        },
      },
    },
  });
  const ids = findings.map((f) => f.ruleId).sort();
  assert.deepEqual(ids, ["SV-001", "SV-002"]);
  assert.ok(findings[0]!.location.jsonPath?.includes("items.items"));
});

test("a nullable object (union type) does not fire SV-002", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: {
          config: {
            type: ["object", "null"],
            properties: { x: { type: "string", enum: ["ok"] } },
          },
        },
      },
    }),
    []
  );
});

test("a nullable array (union type) does not fire SV-003", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: {
          tags: { type: ["array", "null"], items: { type: "string", enum: ["a"] } },
        },
      },
    }),
    []
  );
});

test("a union type containing an invalid primitive fires SV-001", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: {
        config: {
          type: ["object", "sting"],
          properties: { x: { type: "string", enum: ["ok"] } },
        },
      },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["SV-001"]);
  assert.ok(findings[0]!.detail.includes('"sting"'));
});

test("minLength > maxLength fires SV-006", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { q: { type: "string", minLength: 100, maxLength: 5 } },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["SV-006"]);
  assert.ok(findings[0]!.detail.includes("minLength (100)"));
  assert.ok(findings[0]!.detail.includes("maxLength (5)"));
});

test("minimum > maximum and minItems > maxItems fire SV-007", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: { n: { type: "number", minimum: 10, maximum: 1 } },
      },
    }),
    ["SV-007"]
  );
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: {
          list: { type: "array", minItems: 5, maxItems: 2, items: { type: "string" } },
        },
      },
    }),
    ["SV-007"]
  );
});

test("numeric constraint on a non-numeric type fires SV-008", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: { s: { type: "string", minimum: 3 } },
      },
    }),
    ["SV-008"]
  );
});

test("string constraint on a non-string type fires SV-009", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { n: { type: "integer", pattern: "^\\d+$" } },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["SV-009"]);
  assert.ok(findings[0]!.detail.includes("pattern"));
});

test("enum values mismatching the declared type fire SV-010", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { mode: { type: "string", enum: ["fast", 2, true] } },
    },
  });
  assert.deepEqual(findings.map((f) => f.ruleId), ["SV-010"]);
  assert.ok(findings[0]!.detail.includes("2"));
  assert.ok(findings[0]!.detail.includes("true"));
});

test("empty and duplicate enums fire SV-011", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: { mode: { type: "string", enum: [] } },
      },
    }),
    ["SV-011"]
  );
  const dup = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { mode: { type: "string", enum: ["a", "b", "a"] } },
    },
  });
  assert.deepEqual(dup.map((f) => f.ruleId), ["SV-011"]);
  assert.ok(dup[0]!.detail.includes('"a"'));
});

test("a schema with rich but consistent constraints has no contradictions", () => {
  assert.deepEqual(
    ruleIds({
      name: "t",
      inputSchema: {
        type: "object",
        properties: {
          q: { type: "string", minLength: 1, maxLength: 80, pattern: "^[a-z ]+$" },
          n: { type: "integer", minimum: 0, maximum: 100 },
          tags: {
            type: "array",
            minItems: 0,
            maxItems: 10,
            items: { type: "string", enum: ["a", "b"] },
          },
          nullable: { type: ["number", "null"], minimum: 0, enum: [0, 1, null] },
        },
      },
    }),
    []
  );
});

test("schema-validation stops at the nesting depth limit with a warning", () => {
  let node: Record<string, unknown> = { type: "string" };
  for (let i = 0; i < 100; i++) {
    node = { type: "object", properties: { child: node } };
  }
  const warnings: string[] = [];
  const findings = schemaValidationRule.check(
    { name: "deep", inputSchema: node } as unknown as MCPToolDefinition,
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

test("null or scalar schema oddities do not throw", () => {
  const findings = check({
    name: "t",
    inputSchema: {
      type: "object",
      properties: { a: null, b: 5, c: { type: "string", enum: ["ok"] } },
      required: 7,
      items: null,
    },
  });
  assert.ok(Array.isArray(findings));
});
