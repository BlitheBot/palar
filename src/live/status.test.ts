/**
 * Unit tests for probe status resolution.
 *
 * The ordering rule (confirmed > rejected > unconfirmed) is the whole
 * reason this module exists, so it is tested exhaustively over the
 * callback x isError matrix rather than only on the paths that happen to
 * occur against today's fixtures.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveProbeStatus } from "./status.js";
import type { CallbackEvent } from "./oracle.js";
import type { ToolCallCapture } from "./types.js";

const CALLBACK: CallbackEvent = {
  nonce: "abc123",
  receivedAt: new Date("2026-08-18T00:00:00.000Z").toISOString(),
  remoteAddress: "172.18.0.2",
  method: "GET",
  path: "/cb/abc123",
};

const ok: ToolCallCapture = { isError: false, textPreview: "fine" };
const errored: ToolCallCapture = { isError: true, textPreview: "Access denied" };
const unset: ToolCallCapture = { textPreview: "{}" };

test("callback + no error result => confirmed", () => {
  assert.equal(resolveProbeStatus(CALLBACK, ok), "confirmed");
});

test("no callback + isError true => rejected", () => {
  assert.equal(resolveProbeStatus(null, errored), "rejected");
});

test("no callback + isError false => unconfirmed", () => {
  assert.equal(resolveProbeStatus(null, ok), "unconfirmed");
});

test("no callback + isError absent => unconfirmed, never rejected", () => {
  // isError is optional in MCP. Absent must not be read as "rejected"
  // (server-memory's search_nodes returns a normal result with no isError).
  assert.equal(resolveProbeStatus(null, unset), "unconfirmed");
});

/**
 * THE CASE THIS SUITE EXISTS FOR.
 *
 * A successful command injection whose injected command exits nonzero
 * returns isError:true AND fires the callback. Reading isError first would
 * label a proven, oracle-confirmed injection "rejected" — a false negative
 * in the most dangerous direction this tool has.
 *
 * This combination has never been observed in practice, because until
 * e8380c6 the Windows payload branch emitted cmd.exe syntax into a Linux
 * shell and the callback could never fire at all. It is therefore untested
 * by construction unless asserted directly, which is what this does.
 */
test("callback + isError TRUE => confirmed, NOT rejected (injection ran, command exited nonzero)", () => {
  const injectedButFailed: ToolCallCapture = {
    isError: true,
    textPreview: "Command failed: curl: (7) Failed to connect\nexit status 7",
  };
  assert.equal(
    resolveProbeStatus(CALLBACK, injectedButFailed),
    "confirmed",
    "a callback must ALWAYS win over isError — labeling this 'rejected' would hide a " +
      "confirmed command injection behind the failing exit status of its own payload"
  );
});

test("callback + transport failure => confirmed (callback outranks a lost response)", () => {
  // The tool call's response never came back, but the payload demonstrably
  // executed: something reached the oracle carrying this probe's nonce.
  assert.equal(resolveProbeStatus(CALLBACK, { error: "connection closed" }), "confirmed");
});

test("no callback + transport failure => unconfirmed, NOT rejected", () => {
  // { error } means the call never completed, so we do not know whether the
  // handler ran. That is not the target pushing back, and must not be
  // reported as though it were.
  assert.equal(resolveProbeStatus(null, { error: "connection closed" }), "unconfirmed");
});

test("the full callback x isError matrix resolves as specified", () => {
  const matrix: [CallbackEvent | null, ToolCallCapture | { error: string }, string][] = [
    [CALLBACK, ok, "confirmed"],
    [CALLBACK, errored, "confirmed"],
    [CALLBACK, unset, "confirmed"],
    [CALLBACK, { error: "boom" }, "confirmed"],
    [null, ok, "unconfirmed"],
    [null, errored, "rejected"],
    [null, unset, "unconfirmed"],
    [null, { error: "boom" }, "unconfirmed"],
  ];
  for (const [cb, call, expected] of matrix) {
    assert.equal(
      resolveProbeStatus(cb, call),
      expected,
      `callback=${cb ? "yes" : "no"} call=${JSON.stringify(call)} should be ${expected}`
    );
  }
  // Every row with a callback must be confirmed, with no exceptions.
  assert.equal(
    matrix.filter(([cb]) => cb !== null).every(([, , e]) => e === "confirmed"),
    true
  );
});
