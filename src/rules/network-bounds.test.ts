import { test } from "node:test";
import assert from "node:assert/strict";
import { networkBoundsRule } from "./network-bounds.js";
import type { MCPServerConfig } from "../core/types.js";

const ctx = { file: "test.json" };
const check = (server: unknown) =>
  networkBoundsRule.check(server as MCPServerConfig, ctx);
const ruleIds = (server: unknown) => check(server).map((f) => f.ruleId);

// A network block that satisfies the filter rules, for isolating host checks.
const filtered = { egressFilterEnabled: true, egressAllowlist: ["api.example.com"] };

test("missing network block produces NOTHING — absent is not disabled", () => {
  // network.egressFilterEnabled is palar's own manifest key, absent from
  // every real MCP server. Firing on its absence reported the absence of
  // palar metadata at high severity on 100% of real servers.
  assert.deepEqual(ruleIds({ name: "srv" }), []);
});

test("egressFilterEnabled explicitly false produces NB-001 — a stated claim", () => {
  assert.deepEqual(
    ruleIds({ name: "srv", network: { egressFilterEnabled: false } }),
    ["NB-001"]
  );
});

test("empty network object produces nothing — it declares no egress posture", () => {
  assert.deepEqual(ruleIds({ name: "srv", network: {} }), []);
});

test("a network block declaring only exposedHosts does not imply egress is off", () => {
  // Partial posture: the author declared hosts but said nothing about
  // filtering. Silence about egress is still not a claim that egress is
  // unbounded, so NB-001 stays quiet while NB-004 evaluates what WAS stated.
  assert.deepEqual(
    ruleIds({ name: "srv", network: { exposedHosts: ["10.0.0.5"] } }),
    ["NB-004"]
  );
});

test("NB-002/003/004 never fire on an absent declaration", () => {
  // The companion guarantee to NB-001's fix: no NB rule reports on silence.
  assert.deepEqual(ruleIds({ name: "srv" }), []);
  assert.deepEqual(ruleIds({ name: "srv", network: {} }), []);
  assert.deepEqual(ruleIds({ name: "srv", network: { exposedHosts: [] } }), []);
  assert.deepEqual(ruleIds({ name: "srv", network: { egressAllowlist: [] } }), []);
});

test("filter enabled with missing allowlist produces NB-002, not NB-001", () => {
  assert.deepEqual(
    ruleIds({ name: "srv", network: { egressFilterEnabled: true } }),
    ["NB-002"]
  );
});

test("filter enabled with empty allowlist produces NB-002", () => {
  assert.deepEqual(
    ruleIds({
      name: "srv",
      network: { egressFilterEnabled: true, egressAllowlist: [] },
    }),
    ["NB-002"]
  );
});

test("filter enabled with populated allowlist produces nothing", () => {
  assert.deepEqual(ruleIds({ name: "srv", network: filtered }), []);
});

for (const host of ["localhost", "0.0.0.0", "::1", "[::1]:443", "127.0.0.1:8080"]) {
  test(`loopback host ${host} produces NB-003`, () => {
    assert.deepEqual(
      ruleIds({ name: "srv", network: { ...filtered, exposedHosts: [host] } }),
      ["NB-003"]
    );
  });
}

for (const host of ["10.1.2.3", "192.168.1.1", "172.31.0.1", "169.254.169.254"]) {
  test(`private-subnet host ${host} produces NB-004`, () => {
    assert.deepEqual(
      ruleIds({ name: "srv", network: { ...filtered, exposedHosts: [host] } }),
      ["NB-004"]
    );
  });
}

test("public hosts produce no host findings", () => {
  assert.deepEqual(
    ruleIds({
      name: "srv",
      network: { ...filtered, exposedHosts: ["api.example.com", "172.32.0.1"] },
    }),
    []
  );
});

test("a host never fires both NB-003 and NB-004", () => {
  const findings = check({
    name: "srv",
    network: { ...filtered, exposedHosts: ["127.0.0.1"] },
  });
  assert.equal(findings.length, 1);
});

test("string (non-array) exposedHosts does not throw", () => {
  assert.deepEqual(
    ruleIds({
      name: "srv",
      network: { ...filtered, exposedHosts: "127.0.0.1" },
    }),
    []
  );
});

test("non-string host entries are skipped without throwing", () => {
  assert.deepEqual(
    ruleIds({
      name: "srv",
      network: { ...filtered, exposedHosts: [5, null, "10.0.0.1"] },
    }),
    ["NB-004"]
  );
});

test("non-array egressAllowlist does not throw and counts as missing", () => {
  assert.deepEqual(
    ruleIds({
      name: "srv",
      network: { egressFilterEnabled: true, egressAllowlist: "api.example.com" },
    }),
    ["NB-002"]
  );
});
