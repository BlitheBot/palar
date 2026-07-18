import { test } from "node:test";
import assert from "node:assert/strict";
import {
  buildSnapshot,
  diffSnapshots,
  diffSnapshotsDetailed,
} from "./snapshot.js";
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
  const entryA = a.snapshot.tools["t"];
  const entryB = b.snapshot.tools["t"];
  assert.ok(typeof entryA === "object" && typeof entryB === "object");
  assert.equal(entryA.hash, entryB.hash);
});

test("different content produces a different hash", () => {
  const a = buildSnapshot(
    discovered([{ file: "a.json", definition: { name: "t", description: "one" } }])
  );
  const b = buildSnapshot(
    discovered([{ file: "a.json", definition: { name: "t", description: "two" } }])
  );
  const hashA = a.snapshot.tools["t"];
  const hashB = b.snapshot.tools["t"];
  assert.ok(typeof hashA === "object" && typeof hashB === "object");
  assert.notEqual(hashA.hash, hashB.hash);
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

function snapOf(definition: Record<string, unknown>) {
  return buildSnapshot(
    discovered([
      { file: "a.json", definition: definition as unknown as MCPToolDefinition },
    ])
  ).snapshot;
}

const guardedTool = {
  name: "runner",
  description: "Runs an approved task by name.",
  inputSchema: {
    type: "object",
    properties: {
      command: { type: "string", pattern: "^[a-z-]{1,32}$" },
      action: { type: "string", enum: ["start", "stop"] },
      confirm: { type: "boolean" },
    },
    required: ["command", "confirm"],
  },
};

test("removing a pattern is reported as a loosening security regression", () => {
  const loosened = structuredClone(guardedTool) as Record<string, any>;
  delete loosened.inputSchema.properties.command.pattern;
  const diff = diffSnapshotsDetailed(snapOf(guardedTool), snapOf(loosened));
  assert.equal(diff.length, 1);
  const entry = diff[0]!;
  assert.equal(entry.kind, "regressed");
  assert.ok(entry.reason?.includes('pattern removed from parameter "command"'));
  const change = entry.changes.find((c) => c.path === "command");
  assert.equal(change?.classification, "loosening");
});

test("adding a pattern is a tightening, not a regression", () => {
  const before = structuredClone(guardedTool) as Record<string, any>;
  delete before.inputSchema.properties.command.pattern;
  const diff = diffSnapshotsDetailed(snapOf(before), snapOf(guardedTool));
  assert.equal(diff.length, 1);
  assert.equal(diff[0]!.kind, "changed");
  const change = diff[0]!.changes.find((c) => c.path === "command");
  assert.equal(change?.classification, "tightening");
  assert.ok(change?.description.includes("pattern added"));
});

test("a neutral description reword is not flagged as a regression", () => {
  const reworded = structuredClone(guardedTool) as Record<string, any>;
  reworded.description = "Runs a pre-approved task by its name.";
  const diff = diffSnapshotsDetailed(snapOf(guardedTool), snapOf(reworded));
  assert.equal(diff.length, 1);
  assert.equal(diff[0]!.kind, "changed");
  assert.ok(diff[0]!.changes.every((c) => c.classification !== "loosening"));
});

test("enum expansion is reported as loosening with counts", () => {
  const expanded = structuredClone(guardedTool) as Record<string, any>;
  expanded.inputSchema.properties.action.enum = ["start", "stop", "purge", "exec"];
  const diff = diffSnapshotsDetailed(snapOf(guardedTool), snapOf(expanded));
  assert.equal(diff[0]!.kind, "regressed");
  assert.ok(diff[0]!.reason?.includes("enum expanded from 2 to 4 values"));
});

test("removing a required flag is reported as loosening", () => {
  const relaxed = structuredClone(guardedTool) as Record<string, any>;
  relaxed.inputSchema.required = ["command"];
  const diff = diffSnapshotsDetailed(snapOf(guardedTool), snapOf(relaxed));
  assert.equal(diff[0]!.kind, "regressed");
  assert.ok(diff[0]!.reason?.includes("required flag removed"));
});

test("detailed diff still reports added and removed tools", () => {
  const base = snapOf(guardedTool);
  const other = snapOf({ ...structuredClone(guardedTool), name: "other_tool" });
  const diff = diffSnapshotsDetailed(base, other).sort((a, b) =>
    a.toolName.localeCompare(b.toolName)
  );
  assert.deepEqual(
    diff.map((d) => `${d.toolName}:${d.kind}`),
    ["other_tool:added", "runner:removed"]
  );
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
