import { test } from "node:test";
import assert from "node:assert/strict";
import { buildSnapshot, diffSnapshots } from "./snapshot.js";
import type { DiscoveredFiles } from "../discovery/index.js";
import type { MCPToolDefinition } from "../core/types.js";

function discovered(
  tools: { file: string; definition: MCPToolDefinition }[]
): DiscoveredFiles {
  return { tools, servers: [], warnings: [] };
}

test("hashing is key-order independent at every nesting level", () => {
  const a = buildSnapshot(
    discovered([
      {
        file: "a.json",
        definition: {
          name: "t",
          description: "d",
          inputSchema: {
            type: "object",
            properties: { x: { type: "string", pattern: "^a$" } },
          },
        },
      },
    ])
  );
  const b = buildSnapshot(
    discovered([
      {
        file: "a.json",
        definition: {
          inputSchema: {
            properties: { x: { pattern: "^a$", type: "string" } },
            type: "object",
          },
          description: "d",
          name: "t",
        },
      },
    ])
  );
  assert.ok(a.snapshot.tools["t"]);
  assert.equal(a.snapshot.tools["t"], b.snapshot.tools["t"]);
});

test("different content produces a different hash", () => {
  const a = buildSnapshot(
    discovered([{ file: "a.json", definition: { name: "t", description: "one" } }])
  );
  const b = buildSnapshot(
    discovered([{ file: "a.json", definition: { name: "t", description: "two" } }])
  );
  assert.notEqual(a.snapshot.tools["t"], b.snapshot.tools["t"]);
});

test("diffSnapshots reports added, removed, and changed", () => {
  const baseline = {
    createdAt: "2026-01-01T00:00:00Z",
    tools: { keep: "h1", gone: "h2", mod: "h3" },
  };
  const current = {
    createdAt: "2026-01-02T00:00:00Z",
    tools: { keep: "h1", mod: "h3-changed", fresh: "h4" },
  };
  const diff = diffSnapshots(baseline, current).sort((a, b) =>
    a.toolName.localeCompare(b.toolName)
  );
  assert.deepEqual(diff, [
    { toolName: "fresh", kind: "added" },
    { toolName: "gone", kind: "removed" },
    { toolName: "mod", kind: "changed" },
  ]);
});

test("identical snapshots produce an empty diff", () => {
  const snap = { createdAt: "t", tools: { a: "h1" } };
  assert.deepEqual(diffSnapshots(snap, snap), []);
});

test("duplicate tool name produces an overrides warning", () => {
  const { snapshot, warnings } = buildSnapshot(
    discovered([
      { file: "first.json", definition: { name: "dup", description: "one" } },
      { file: "second.json", definition: { name: "dup", description: "two" } },
    ])
  );
  assert.equal(Object.keys(snapshot.tools).length, 1);
  assert.equal(warnings.length, 1);
  assert.ok(warnings[0]!.includes('duplicate tool name "dup"'));
  assert.ok(warnings[0]!.includes("second.json overrides the one from first.json"));
});
