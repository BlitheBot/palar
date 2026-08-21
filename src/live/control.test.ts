/**
 * Unit tests for the control-call side-effect gate.
 *
 * The gate is the load-bearing part of this feature: everything else only
 * changes how a probe is LABELLED, while this decides whether palar makes
 * a real call to a real tool. So the tests are written around the two
 * properties that make it safe rather than around coverage of its
 * branches:
 *
 *   1. An annotation can only ever SUBTRACT permission. A server that
 *      claims to be harmless gets no more access than one that says
 *      nothing, because a safety claim is exactly what a hostile server
 *      would write.
 *   2. Every veto is independent and sufficient. A tool has to clear all
 *      of them, so no single lie or oversight opens the path.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildBenignArguments, controlGateDecision } from "./control.js";
import { benignValueFor, type LiveTool } from "./probes.js";
import type { MCPToolAnnotations } from "../core/types.js";

function tool(name: string, annotations?: MCPToolAnnotations): LiveTool {
  return { name, inputSchema: { type: "object" }, ...(annotations ? { annotations } : {}) };
}

test("a plain stdio tool with no annotations is allowed", () => {
  assert.equal(controlGateDecision(tool("summarize_text"), "stdio").allowed, true);
});

test("SSE is refused outright, whatever the tool looks like", () => {
  // No sandbox exists for an SSE target, so there is no version of this
  // call whose blast radius palar can bound.
  const decision = controlGateDecision(tool("summarize_text"), "sse");
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /SSE target/);
});

test("a declared destructiveHint:true vetoes", () => {
  const decision = controlGateDecision(tool("tidy_up", { destructiveHint: true }), "stdio");
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /destructiveHint/);
});

test("a SAFETY claim grants nothing on a name that is vetoed", () => {
  // The core asymmetry. `readOnlyHint: true` + `destructiveHint: false` is
  // the most reassuring thing a server can say, and it is precisely what a
  // server lying to get called would say. It must not buy access.
  const claims: MCPToolAnnotations = { readOnlyHint: true, destructiveHint: false };
  const decision = controlGateDecision(tool("delete_file", claims), "stdio");
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /delete/);
});

test("a SAFETY claim does not rescue an SSE target either", () => {
  const claims: MCPToolAnnotations = { readOnlyHint: true, destructiveHint: false };
  assert.equal(controlGateDecision(tool("list_items", claims), "sse").allowed, false);
});

test("silence is not permission where the name is dangerous", () => {
  // The spec's default for an undeclared destructiveHint is `true`, so an
  // undeclared hint is not evidence of safety. The name veto still applies.
  for (const name of ["delete_file", "send_email", "start_process", "git_push", "run_command"]) {
    assert.equal(controlGateDecision(tool(name), "stdio").allowed, false, name);
  }
});

test("the name veto is case- and separator-insensitive", () => {
  assert.equal(controlGateDecision(tool("filesDeleteBatch"), "stdio").allowed, false);
  assert.equal(controlGateDecision(tool("FILE_REMOVE"), "stdio").allowed, false);
});

test("a declared destructiveHint:false does not override the name veto", () => {
  // Same asymmetry as above, stated on the hint palar consults: it is read
  // only for `true`. `false` is a safety claim and is never consulted.
  const decision = controlGateDecision(tool("purge_cache", { destructiveHint: false }), "stdio");
  assert.equal(decision.allowed, false);
  assert.match(decision.reason, /purge/);
});

test("a non-boolean hint is treated as undeclared, not coerced", () => {
  // Mirrors core/annotations.ts readHint(): the string "true" is not the
  // boolean the spec describes. It must not veto (it is not a declaration)
  // and it must not grant (nothing ever grants).
  const weird = { destructiveHint: "true" } as unknown as MCPToolAnnotations;
  assert.equal(controlGateDecision(tool("summarize_text", weird), "stdio").allowed, true);
});

test("benign arguments cover required properties only", () => {
  // Same rule as buildProbeArguments: an optional property is a knob, and
  // filling one makes the control a different call than the probe it is
  // the control for.
  const t: LiveTool = {
    name: "fetch_url",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string" },
        apiKey: { type: "string" },
        retries: { type: "integer" },
      },
      required: ["url", "retries"],
    },
  };
  const args = buildBenignArguments(t, "A benign sentence.", benignValueFor);
  assert.deepEqual(Object.keys(args).sort(), ["retries", "url"]);
  assert.equal(args.url, "A benign sentence.");
  assert.equal(typeof args.retries, "number");
});

test("benign arguments respect a declared enum rather than pasting prose into it", () => {
  // The desktop-commander shape: a free-form sentence in an enum'd field
  // is what made a bounced argument-validation error look like the tool's
  // own behaviour.
  const t: LiveTool = {
    name: "start_process",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string" },
        origin: { type: "string", enum: ["ui", "llm"] },
      },
      required: ["command", "origin"],
    },
  };
  const args = buildBenignArguments(t, "A benign sentence.", benignValueFor);
  assert.equal(args.origin, "ui");
  assert.equal(args.command, "A benign sentence.");
});

test("the payload never appears in a control call", () => {
  // The control's entire evidentiary value is that it carries no payload.
  const t: LiveTool = {
    name: "run_diagnostic",
    inputSchema: {
      type: "object",
      properties: { hostname: { type: "string" } },
      required: ["hostname"],
    },
  };
  const args = buildBenignArguments(t, "A benign sentence.", benignValueFor);
  const serialized = JSON.stringify(args);
  for (const marker of [";", "|", "curl", "http://", "$(", "`"]) {
    assert.equal(serialized.includes(marker), false, `control args contained ${marker}`);
  }
});

test("the gate does not gut the feature: the motivating case still gets a control", () => {
  // playwright-mcp is why `inconclusive` exists at all. If the verb list
  // grew until its tools were vetoed too, the whole instrument would be
  // dead on arrival while still looking implemented — so the tools whose
  // probes must stop reading as refusals are asserted allowed here.
  for (const name of ["browser_navigate", "browser_take_screenshot"]) {
    assert.equal(controlGateDecision(tool(name), "stdio").allowed, true, name);
  }
  // Same for the read-shaped tools in palar's own fixture.
  for (const name of ["fetch_url", "summarize_text", "read_file", "search_nodes"]) {
    assert.equal(controlGateDecision(tool(name), "stdio").allowed, true, name);
  }
});

test("the gate does veto the execution-shaped tools in the sample", () => {
  for (const name of ["start_process", "run_diagnostic", "execute_command", "write_file"]) {
    assert.equal(controlGateDecision(tool(name), "stdio").allowed, false, name);
  }
});
