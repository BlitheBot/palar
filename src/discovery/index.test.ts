import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { discover } from "./index.js";

async function withTempDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "mcpguard-test-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

async function writeToolFile(
  dir: string,
  basename: string,
  content: string
): Promise<void> {
  await mkdir(join(dir, "tools"), { recursive: true });
  await writeFile(join(dir, "tools", basename), content, "utf8");
}

test("malformed JSON is skipped with a warning, not thrown", async () => {
  await withTempDir(async (dir) => {
    await writeToolFile(dir, "bad.json", "{ this is not json");
    const result = await discover([dir]);
    assert.equal(result.tools.length, 0);
    assert.ok(result.warnings.some((w) => w.includes("malformed JSON")));
  });
});

test("non-object top-level JSON is skipped with a warning", async () => {
  await withTempDir(async (dir) => {
    await writeToolFile(dir, "number.json", "5");
    const result = await discover([dir]);
    assert.equal(result.tools.length, 0);
    assert.ok(result.warnings.some((w) => w.includes("non-object entry")));
  });
});

test("an array of tools is normalized to one entry per tool", async () => {
  await withTempDir(async (dir) => {
    await writeToolFile(
      dir,
      "many.json",
      JSON.stringify([{ name: "one" }, { name: "two" }])
    );
    const result = await discover([dir]);
    assert.deepEqual(
      result.tools.map((t) => t.definition.name).sort(),
      ["one", "two"]
    );
  });
});

test("duplicate tool names across files produce a declared-N-times warning", async () => {
  await withTempDir(async (dir) => {
    await writeToolFile(dir, "a.json", JSON.stringify({ name: "dup" }));
    await writeToolFile(dir, "b.json", JSON.stringify({ name: "dup" }));
    const result = await discover([dir]);
    assert.equal(result.tools.length, 2);
    const warning = result.warnings.find((w) =>
      w.includes('duplicate tool name "dup" declared 2 times')
    );
    assert.ok(warning, `warnings were: ${JSON.stringify(result.warnings)}`);
    assert.ok(warning.includes("a.json") && warning.includes("b.json"));
  });
});

test("a file matching both tool and server globs is audited as both, with a warning", async () => {
  await withTempDir(async (dir) => {
    await writeToolFile(
      dir,
      "both.mcp-server.json",
      JSON.stringify({ name: "ambiguous" })
    );
    const result = await discover([dir]);
    assert.equal(result.tools.length, 1);
    assert.equal(result.servers.length, 1);
    assert.ok(
      result.warnings.some((w) =>
        w.includes("matched both tool and server patterns")
      )
    );
  });
});

test("oversized files are skipped via stat with a warning, never read", async () => {
  await withTempDir(async (dir) => {
    const big = JSON.stringify({ name: "big_tool", description: "x".repeat(500) });
    await writeToolFile(dir, "big.json", big);
    const result = await discover([dir], { maxFileSize: 100 });
    assert.equal(result.tools.length, 0);
    const warning = result.warnings.find((w) => w.includes("exceeds"));
    assert.ok(warning, `warnings were: ${JSON.stringify(result.warnings)}`);
    assert.ok(warning.includes("100-byte limit"));
    const ok = await discover([dir], { maxFileSize: 10_000 });
    assert.equal(ok.tools.length, 1);
  });
});

test("entries without a string name are skipped with a warning", async () => {
  await withTempDir(async (dir) => {
    await writeToolFile(dir, "unnamed.json", JSON.stringify({ description: "x" }));
    const result = await discover([dir]);
    assert.equal(result.tools.length, 0);
    assert.ok(result.warnings.some((w) => w.includes('no "name" string')));
  });
});
