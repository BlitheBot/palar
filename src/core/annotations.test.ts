import { test } from "node:test";
import assert from "node:assert/strict";
import {
  ANNOTATION_HINTS,
  declaredHints,
  describeHint,
  readHint,
  resolveToolTitle,
  titleField,
} from "./annotations.js";
import type { MCPToolDefinition } from "./types.js";

test("a top-level title is resolved and its position reported", () => {
  const resolved = resolveToolTitle({ name: "t", title: "Fetch URL" });
  assert.deepEqual(resolved, { declared: true, text: "Fetch URL", position: "title" });
});

test("an annotations.title is resolved and its position reported", () => {
  const resolved = resolveToolTitle({ name: "t", annotations: { title: "Fetch URL" } });
  assert.deepEqual(resolved, {
    declared: true,
    text: "Fetch URL",
    position: "annotations.title",
  });
});

test("the top-level title wins when both positions are present", () => {
  const resolved = resolveToolTitle({
    name: "t",
    title: "Newer",
    annotations: { title: "Older" },
  });
  assert.equal(resolved.declared && resolved.text, "Newer");
  assert.equal(resolved.declared && resolved.position, "title");
});

test("no title declared reports undeclared, and never falls back to the name", () => {
  const resolved = resolveToolTitle({ name: "fetch_url" });
  assert.deepEqual(resolved, { declared: false });
});

test("a non-string title is treated as undeclared rather than coerced", () => {
  const resolved = resolveToolTitle({ name: "t", title: 42 as unknown as string });
  assert.deepEqual(resolved, { declared: false });
});

test("titleField carries text and position for a tool definition", () => {
  const tool: MCPToolDefinition = { name: "t", annotations: { title: "Label" } };
  assert.deepEqual(titleField(tool), { text: "Label", position: "annotations.title" });
  assert.equal(titleField({ name: "t" }), null);
});

test("readHint returns declared booleans and undefined for anything else", () => {
  const tool = { name: "t", annotations: { readOnlyHint: true, openWorldHint: false } };
  assert.equal(readHint(tool, "readOnlyHint"), true);
  assert.equal(readHint(tool, "openWorldHint"), false);
  assert.equal(readHint(tool, "destructiveHint"), undefined);
});

test("a hint written as a string is undeclared, not coerced to a boolean", () => {
  const tool = { name: "t", annotations: { readOnlyHint: "true" as unknown as boolean } };
  assert.equal(readHint(tool, "readOnlyHint"), undefined);
});

test("declaredHints omits every hint the server did not declare", () => {
  const hints = declaredHints({ name: "t", annotations: { idempotentHint: false } });
  assert.deepEqual(hints, { idempotentHint: false });
  assert.deepEqual(declaredHints({ name: "t" }), {});
});

/**
 * The load-bearing one. The spec's defaults are all on the dangerous side,
 * so rendering an absent hint as its default would print a value the server
 * never wrote — and would make `scan` and `live` agree on a claim neither
 * of them actually read.
 */
test("an undeclared hint renders as 'not declared', never as its spec default", () => {
  assert.equal(describeHint(undefined), "not declared");
  assert.equal(describeHint(true), "true");
  assert.equal(describeHint(false), "false");
  // Specifically: not "false", which is readOnlyHint's spec default.
  assert.notEqual(describeHint(readHint({ name: "t" }, "readOnlyHint")), "false");
});

test("ANNOTATION_HINTS covers exactly the four spec hints", () => {
  assert.deepEqual(
    [...ANNOTATION_HINTS].sort(),
    ["destructiveHint", "idempotentHint", "openWorldHint", "readOnlyHint"]
  );
});
