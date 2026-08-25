import { test } from "node:test";
import assert from "node:assert/strict";
import {
  isLoopbackHost,
  extractHost,
  classifyPayloadEligibility,
  type PayloadEligibility,
} from "./eligibility.js";
import type { MCPServerConfig } from "../core/types.js";

// ---- isLoopbackHost: the literal host matcher --------------------------

test("127.0.0.1 is loopback", () => {
  assert.equal(isLoopbackHost("127.0.0.1"), true);
});

test("the whole 127.0.0.0/8 range is loopback, not just .0.0.1", () => {
  assert.equal(isLoopbackHost("127.0.0.53"), true);
  assert.equal(isLoopbackHost("127.1.2.3"), true);
  assert.equal(isLoopbackHost("127.255.255.255"), true);
});

test("::1 and its ::ffff:127.x mapped form are loopback", () => {
  assert.equal(isLoopbackHost("::1"), true);
  assert.equal(isLoopbackHost("::ffff:127.0.0.1"), true);
});

test("localhost is loopback as a literal", () => {
  assert.equal(isLoopbackHost("localhost"), true);
  assert.equal(isLoopbackHost("LOCALHOST"), true);
});

test("a routable address is not loopback", () => {
  assert.equal(isLoopbackHost("10.0.0.5"), false);
  assert.equal(isLoopbackHost("192.168.1.10"), false);
  assert.equal(isLoopbackHost("203.0.113.7"), false);
  assert.equal(isLoopbackHost("0.0.0.0"), false);
});

test("a hostname that would RESOLVE to loopback is not matched (no DNS)", () => {
  // localhost.example.com commonly resolves to 127.0.0.1, but we match the
  // literal only — see the module docstring on TOCTOU.
  assert.equal(isLoopbackHost("localhost.example.com"), false);
  assert.equal(isLoopbackHost("my-loopback.internal"), false);
});

test("octets above 255 are not a valid loopback address", () => {
  assert.equal(isLoopbackHost("127.0.0.999"), false);
  assert.equal(isLoopbackHost("999.0.0.1"), false);
});

// ---- extractHost: strips credentials, brackets, port -------------------

test("extractHost strips credentials, port, and IPv6 brackets", () => {
  assert.equal(extractHost("http://user:pass@127.0.0.1:3000/sse"), "127.0.0.1");
  assert.equal(extractHost("http://[::1]:8080/sse"), "::1");
  assert.equal(extractHost("https://example.com:443/mcp"), "example.com");
});

test("extractHost returns null for an unparseable url", () => {
  assert.equal(extractHost("not a url"), null);
  assert.equal(extractHost(""), null);
});

// ---- classifyPayloadEligibility: the three cases -----------------------

const stdioServer: MCPServerConfig = { name: "s", command: "node", args: ["x.js"] };
function sse(url: string | undefined): MCPServerConfig {
  return { name: "s", transport: "sse", url };
}

test("stdio is always eligible and sandboxed", () => {
  const e = classifyPayloadEligibility(stdioServer);
  assert.deepEqual(e, { eligible: true, sandboxed: true, kind: "stdio" });
});

test("an undeclared transport is treated as stdio-eligible", () => {
  const e = classifyPayloadEligibility({ name: "s", command: "node" });
  assert.equal(e.eligible, true);
  assert.equal((e as Extract<PayloadEligibility, { kind: "stdio" }>).kind, "stdio");
});

test("loopback SSE is eligible but NOT sandboxed", () => {
  const e = classifyPayloadEligibility(sse("http://127.0.0.1:3000/sse"));
  assert.equal(e.eligible, true);
  assert.equal(e.eligible && e.sandboxed, false);
  assert.equal(e.eligible && e.kind, "sse-loopback");
});

test("localhost and ::1 SSE are eligible loopback", () => {
  assert.equal(classifyPayloadEligibility(sse("http://localhost:8080/sse")).eligible, true);
  assert.equal(classifyPayloadEligibility(sse("http://[::1]:8080/sse")).eligible, true);
});

test("credentials in front of a loopback host still classify as loopback", () => {
  const e = classifyPayloadEligibility(sse("http://user:pw@127.0.0.1:9000/sse"));
  assert.equal(e.eligible, true);
  assert.equal(e.eligible && e.kind, "sse-loopback");
});

test("remote SSE is NOT eligible and carries a notice naming the host", () => {
  const e = classifyPayloadEligibility(sse("https://mcp.example.com/sse"));
  assert.equal(e.eligible, false);
  assert.equal(e.eligible, false);
  if (!e.eligible) {
    assert.equal(e.kind, "sse-remote");
    assert.equal(e.host, "mcp.example.com");
    assert.match(e.notice, /NO payload sent/);
    assert.match(e.notice, /mcp\.example\.com/);
  }
});

test("a private-range SSE host is remote (not loopback)", () => {
  const e = classifyPayloadEligibility(sse("http://192.168.1.50:3000/sse"));
  assert.equal(e.eligible, false);
});

test("an SSE target with no url is ineligible rather than a crash", () => {
  const e = classifyPayloadEligibility(sse(undefined));
  assert.equal(e.eligible, false);
  if (!e.eligible) assert.equal(e.host, null);
});
