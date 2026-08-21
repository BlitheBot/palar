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

/**
 * Annotation drift.
 *
 * `claim-relaxed` exists because the other three values describe a
 * constraint the server enforces, and an annotation describes only what the
 * server says about itself. These tests pin both that the label is applied
 * where a rug pull is expressed in claims, and — more importantly — that it
 * is NOT applied in the direction where a client ends up gating harder.
 */
function snapshotOf(definition: MCPToolDefinition) {
  return buildSnapshot(discovered([{ file: "a.json", definition }])).snapshot;
}

const BASE_SCHEMA = {
  type: "object",
  properties: { hostname: { type: "string" } },
  required: ["hostname"],
};

test("declaring readOnlyHint: true where nothing was declared is claim-relaxed", () => {
  const before = snapshotOf({ name: "t", inputSchema: BASE_SCHEMA });
  const after = snapshotOf({
    name: "t",
    annotations: { readOnlyHint: true },
    inputSchema: BASE_SCHEMA,
  });

  const [entry] = diffSnapshotsDetailed(before, after);
  assert.equal(entry!.kind, "regressed");
  const change = entry!.changes.find((c) => c.description.includes("readOnlyHint"));
  assert.equal(change!.classification, "claim-relaxed");
  // Phrased as a claim, so a reader can tell it from a verified change
  // without knowing the vocabulary.
  assert.match(change!.description, /the server now claims readOnlyHint: true/);
  assert.match(change!.description, /nothing enforces/);
});

test("flipping destructiveHint true -> false is claim-relaxed", () => {
  const before = snapshotOf({
    name: "t",
    annotations: { destructiveHint: true },
    inputSchema: BASE_SCHEMA,
  });
  const after = snapshotOf({
    name: "t",
    annotations: { destructiveHint: false },
    inputSchema: BASE_SCHEMA,
  });

  const [entry] = diffSnapshotsDetailed(before, after);
  assert.equal(entry!.kind, "regressed");
  assert.match(entry!.reason!, /the server now claims destructiveHint: false/);
  assert.match(entry!.reason!, /previously true/);
});

test("openWorldHint true -> false is claim-relaxed; the reverse is neutral", () => {
  const closed = snapshotOf({
    name: "t",
    annotations: { openWorldHint: false },
    inputSchema: BASE_SCHEMA,
  });
  const open = snapshotOf({
    name: "t",
    annotations: { openWorldHint: true },
    inputSchema: BASE_SCHEMA,
  });

  const relaxing = diffSnapshotsDetailed(open, closed)[0]!;
  assert.equal(relaxing.kind, "regressed");
  assert.equal(
    relaxing.changes.find((c) => c.description.includes("openWorldHint"))!.classification,
    "claim-relaxed"
  );

  // A tool newly declaring itself open-world makes its client gate harder.
  // No rug-pull shape, so no label — but the move is still recorded.
  const widening = diffSnapshotsDetailed(closed, open)[0]!;
  assert.equal(widening.kind, "changed");
  assert.equal(
    widening.changes.find((c) => c.description.includes("openWorldHint"))!.classification,
    "neutral"
  );
});

test("withdrawing a safety claim is neutral, not a regression", () => {
  const claimed = snapshotOf({
    name: "t",
    annotations: { readOnlyHint: true },
    inputSchema: BASE_SCHEMA,
  });
  const silent = snapshotOf({ name: "t", inputSchema: BASE_SCHEMA });

  const [entry] = diffSnapshotsDetailed(claimed, silent);
  assert.equal(entry!.kind, "changed");
  const change = entry!.changes.find((c) => c.description.includes("readOnlyHint"))!;
  assert.equal(change.classification, "neutral");
  assert.match(change.description, /no longer declares readOnlyHint/);
});

test("a claim relaxation and a schema loosening both reach the reason line", () => {
  const before = snapshotOf({
    name: "t",
    annotations: { readOnlyHint: false },
    inputSchema: BASE_SCHEMA,
  });
  const after = snapshotOf({
    name: "t",
    annotations: { readOnlyHint: true },
    inputSchema: { type: "object", properties: { hostname: { type: "string" } } },
  });

  const [entry] = diffSnapshotsDetailed(before, after);
  assert.equal(entry!.kind, "regressed");
  assert.match(entry!.reason!, /required flag removed/);
  assert.match(entry!.reason!, /the server now claims readOnlyHint: true/);
});

test("an annotation-only flip is detected at all — the hash has to move", () => {
  // The regression guard for the whole feature: without annotations in the
  // hashed material, diffSnapshots() reports no change and nothing is ever
  // compared.
  const before = snapshotOf({ name: "t", inputSchema: BASE_SCHEMA });
  const after = snapshotOf({
    name: "t",
    annotations: { readOnlyHint: true },
    inputSchema: BASE_SCHEMA,
  });
  assert.deepEqual(diffSnapshots(before, after), [{ toolName: "t", kind: "changed" }]);
});

test("a tool declaring neither title nor annotations hashes as it always did", () => {
  // Backward compatibility: an old baseline must not read as wholesale
  // drift the first time a newer palar snapshots the same unchanged tools.
  const snapshot = snapshotOf({ name: "t", description: "d", inputSchema: BASE_SCHEMA });
  const entry = snapshot.tools["t"];
  assert.equal(typeof entry, "object");
  assert.ok(!("title" in (entry as object)), "title key should be absent");
  assert.ok(!("annotations" in (entry as object)), "annotations key should be absent");
  // Pinned rather than recomputed: the point is that the hashed material
  // for a tool declaring neither field is byte-identical to what palar
  // hashed before title and annotations joined it. Recomputing with the
  // same code would agree with itself no matter what changed.
  assert.equal(
    (entry as { hash: string }).hash,
    "254d0879da9ae9bd7c1291496f5df3b2163f6745e31109222bf0100e5aeb34f6"
  );
});

test("a display title change is reported with both values and stays neutral", () => {
  const before = snapshotOf({ name: "t", title: "Fetch URL", inputSchema: BASE_SCHEMA });
  const after = snapshotOf({ name: "t", title: "Fetch anything", inputSchema: BASE_SCHEMA });

  const [entry] = diffSnapshotsDetailed(before, after);
  assert.equal(entry!.kind, "changed");
  const change = entry!.changes.find((c) => c.description.includes("display title"))!;
  assert.equal(change.classification, "neutral");
  assert.match(change.description, /"Fetch anything"/);
  assert.match(change.description, /"Fetch URL"/);
});

test("moving a title between its two spec positions is not a title change", () => {
  const before = snapshotOf({
    name: "t",
    annotations: { title: "Fetch URL" },
    inputSchema: BASE_SCHEMA,
  });
  const after = snapshotOf({ name: "t", title: "Fetch URL", inputSchema: BASE_SCHEMA });

  const [entry] = diffSnapshotsDetailed(before, after);
  // The raw bytes moved, so the hash moved and the tool reads "changed" —
  // but the resolved title is identical, so nothing is described as having
  // changed about it. Same shape as a same-length description reword.
  assert.equal(entry!.kind, "changed");
  assert.deepEqual(entry!.changes, []);
});
