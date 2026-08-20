#!/usr/bin/env bash
#
# Docker Desktop isolation canary — the evidence basis for palar's
# containment claims on the Docker Desktop (Windows/WSL2) backend.
#
# WHY THIS EXISTS AS A SCRIPT AND NOT A WORKFLOW
# ----------------------------------------------
# .github/workflows/canary.yml verifies the NATIVE LINUX ENGINE path daily.
# It cannot verify this one: no hosted CI runner offers Docker Desktop as a
# backend. GitHub's runners are native-Engine VMs — which is precisely why
# that canary exercises the Linux path — and Docker Desktop's licensing and
# nested-virtualisation requirements rule out installing it on one.
#
# So the backend whose containment depends on the most Desktop-specific
# machinery (host.docker.internal, the host-proxy IP resolved fresh per scan
# in resolveDockerDesktopHostProxyIp) is the one that can only ever be
# re-established BY HAND. This script is that hand-check, written down so it
# is repeatable rather than remembered.
#
# IT AGES. The date in src/live/sandbox.ts and README.md is the age of the
# evidence, not a claim about today. Nothing re-runs this on its own.
# Whoever needs the claim to be current runs this and updates both dates.
# A failure here is a published claim that needs retracting — in the docs
# and in the project site's copy — not a flaky test to re-run.
#
# WHAT IT ASSERTS, AND WHY EACH PART IS LOAD-BEARING
# ---------------------------------------------------
# The firewall is verified by a PAIR of observations that only hold together
# if netfilter is genuinely discriminating:
#
#   POSITIVE  the oracle callback lands (the sandbox reached the host on the
#             one ACCEPTed port), and
#   NEGATIVE  a host sentinel listener on a different port is unreachable
#             from that same container.
#
# Either alone is worthless. "Callback landed" with no negative control
# cannot distinguish a working firewall from no firewall. "Connection
# refused" with no positive control cannot distinguish a working firewall
# from a container whose networking is simply broken.
#
# THE PROBE RUNS INSIDE THE LIVE SANDBOX, via `docker exec` into the running
# mcpg-* container. This is deliberate and is the canonical placement: it
# measures what the TARGET can reach, which is the thing the containment
# claim is about. A probe from a sibling shell on the host measures what a
# different process on a different network path can reach, and would pass
# even if the sandbox's own egress were wide open. Do not "simplify" this
# back to a second shell.
#
# Usage:  bash scripts/desktop-canary.sh          (from anywhere in the repo)
# Needs:  Docker Desktop running, `npm run build` already done, and the
#         fixture's own deps installed (cd fixtures/vuln-server && npm ci).
#
set -uo pipefail

# Git Bash on Windows rewrites /target/... into a Windows path before it
# reaches `docker exec`. That is the container's path, not the host's.
export MSYS_NO_PATHCONV=1

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT" || exit 1

WORK="$(mktemp -d)"
PROBE_SRC="fixtures/vuln-server/canary-probe.mjs"

# Two names for the same directory. Under Git Bash on Windows, `mktemp -d`
# returns an MSYS path (/tmp/tmp.XXXX) that the native node.exe resolves as
# C:\tmp\tmp.XXXX — a path that does not exist. Shell redirections take
# $WORK; anything handed to node takes $NODE_WORK. On Linux they are equal
# and this collapses to a no-op.
if command -v cygpath >/dev/null 2>&1; then
  NODE_WORK="$(cygpath -m "$WORK")"
else
  NODE_WORK="$WORK"
fi

# Below Linux's ephemeral range (32768-60999) on purpose: CallbackOracle
# binds with listen(0), so the kernel draws the oracle's real port from that
# range and can never collide with this sentinel. A collision would make the
# negative control silently test the ACCEPTed port instead.
SENTINEL_PORT="${SENTINEL_PORT:-19099}"

# Slow DNS is the regression this bound exists to catch — see the assertion
# block for why the error code alone cannot catch it.
DNS_FAST_MS="${DNS_FAST_MS:-1000}"

FAILURES=0
fail() { echo "FAIL: $*" >&2; FAILURES=$((FAILURES + 1)); }
ok()   { echo "  ok: $*"; }

cleanup() {
  if [ -n "${SENTINEL_PID:-}" ]; then kill "$SENTINEL_PID" 2>/dev/null; fi
  rm -f "$PROBE_SRC"
  rm -rf "$WORK"
}
trap cleanup EXIT

# =====================================================================
# 0. Backend check. Running this on native Engine yields a green result
#    that is evidence for the OTHER backend — already covered by the
#    daily canary — and would be filed under the wrong date.
# =====================================================================
echo "=== backend ==="
docker context show
DOCKER_NAME="$(docker info --format '{{.Name}}' 2>/dev/null)"
docker info --format 'ServerOS={{.OSType}} Kernel={{.KernelVersion}} Name={{.Name}} Version={{.ServerVersion}}'
if [ "$DOCKER_NAME" != "docker-desktop" ]; then
  echo "REFUSING: docker info Name is '$DOCKER_NAME', not 'docker-desktop'." >&2
  echo "This script is the DOCKER DESKTOP evidence basis. The native Linux" >&2
  echo "Engine path is covered by .github/workflows/canary.yml instead." >&2
  exit 2
fi

# =====================================================================
# 1. The in-sandbox probe.
# =====================================================================
cat > "$PROBE_SRC" <<'PROBE'
import net from "node:net";
import dns from "node:dns";
import { readFileSync } from "node:fs";

const sentinelPort = Number(process.argv[2]);
const out = {
  probed: true,
  hostIp: null,
  hostListenerReachable: null,
  tcpErrorCode: null,
  tcpElapsedMs: null,
  dnsResolved: null,
  dnsErrorCode: null,
  dnsElapsedMs: null,
  notes: [],
};

// sandbox.ts pins host.docker.internal via --add-host, i.e. /etc/hosts.
// Reading it directly is the only option that works: the sandbox has no
// resolver at all (--dns 127.0.0.1, nothing listening), by design.
try {
  const line = readFileSync("/etc/hosts", "utf8")
    .split("\n")
    .find((l) => /\bhost\.docker\.internal\b/.test(l));
  out.hostIp = line ? line.trim().split(/\s+/)[0] : null;
} catch (e) {
  out.notes.push("hosts:" + e.code);
}

// (a) NEGATIVE CONTROL. The distinction the assertions care about:
// ECONNREFUSED is the REJECT signature — the chain's
// `--reject-with icmp-port-unreachable` answering immediately — whereas a
// DROP rule presents as the 5s timeout below. Both are "unreachable"; only
// one matches what sandbox.ts claims to install.
out.hostListenerReachable = await new Promise((resolve) => {
  if (!out.hostIp) {
    out.notes.push("no host.docker.internal in /etc/hosts");
    return resolve(null);
  }
  const started = process.hrtime.bigint();
  const mark = () => {
    out.tcpElapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    return Math.round(out.tcpElapsedMs);
  };
  const sock = net.connect({ host: out.hostIp, port: sentinelPort });
  const finish = (v) => { sock.destroy(); resolve(v); };
  sock.setTimeout(5000, () => { out.tcpErrorCode = "TIMEOUT"; out.notes.push("tcp:timeout@" + mark() + "ms"); finish(false); });
  sock.once("connect", () => { out.tcpErrorCode = "CONNECTED"; out.notes.push("tcp:CONNECTED@" + mark() + "ms"); finish(true); });
  sock.once("error", (e) => { out.tcpErrorCode = e.code; out.notes.push("tcp:" + e.code + "@" + mark() + "ms"); finish(false); });
});

// (b) DNS must not resolve, and must fail FAST.
//
// BLACKHOLE_DNS points the container at its own loopback where nothing
// listens, so the UDP query draws an immediate ICMP port-unreachable.
// getaddrinfo() does not surface that as ECONNREFUSED — it maps it to
// EAI_AGAIN — so EAI_AGAIN is the expected code, and its absence rather
// than its presence would be the surprise.
//
// Elapsed ms is recorded because THE CODE ALONE PROVES NOTHING: EAI_AGAIN
// is equally what a resolver that genuinely reached out and timed out
// returns. A blackhole that works and a blackhole that has silently stopped
// working are indistinguishable by error code, and separable only by time.
// Fast EAI_AGAIN is the success shape; slow EAI_AGAIN is the regression.
out.dnsResolved = await new Promise((resolve) => {
  const started = process.hrtime.bigint();
  const mark = () => {
    out.dnsElapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    return Math.round(out.dnsElapsedMs);
  };
  const timer = setTimeout(() => { out.dnsErrorCode = "TIMEOUT"; out.notes.push("dns:timeout@" + mark() + "ms"); resolve(null); }, 5000);
  dns.lookup("example.com", (err, addr) => {
    clearTimeout(timer);
    if (err) { out.dnsErrorCode = err.code; out.notes.push("dns:" + err.code + "@" + mark() + "ms"); resolve(false); }
    else { out.dnsErrorCode = null; out.notes.push("dns:RESOLVED " + addr + "@" + mark() + "ms"); resolve(true); }
  });
});

console.log(JSON.stringify(out));
PROBE

# =====================================================================
# 2. Host sentinel listener.
# =====================================================================
#
# Bound 0.0.0.0 so it genuinely listens on the address the sandbox would
# reach the host through. Bound to loopback only, the negative control would
# "pass" because nothing was listening rather than because netfilter
# refused — the exact false negative this must not produce.
cat > "$WORK/sentinel.mjs" <<'SENTINEL'
import net from "node:net";
const port = Number(process.env.SENTINEL_PORT);
// The per-socket error handler is not optional: the liveness checks below
// disconnect abruptly, and an unhandled ECONNRESET would kill the sentinel
// mid-run. It would then be dead during the probe, and the probe would
// report ECONNREFUSED — a PASS, for entirely the wrong reason.
const srv = net.createServer((s) => { s.on("error", () => {}); s.end("sentinel\n"); });
srv.on("error", (e) => { console.error("sentinel server error:", e.code); process.exit(1); });
srv.listen(port, "0.0.0.0", () => console.log("sentinel listening on 0.0.0.0:" + port));
setInterval(() => {}, 1 << 30);
SENTINEL

cat > "$WORK/ping-sentinel.mjs" <<'PING'
import net from "node:net";
const s = net.connect({ host: "127.0.0.1", port: Number(process.env.SENTINEL_PORT) });
s.once("connect", () => { s.end(); process.exit(0); });
s.once("error", () => process.exit(1));
setTimeout(() => process.exit(1), 4000);
PING

SENTINEL_PORT="$SENTINEL_PORT" node "$NODE_WORK/sentinel.mjs" > "$WORK/sentinel.log" 2>&1 &
SENTINEL_PID=$!

echo
echo "=== sentinel liveness (BEFORE) ==="
SENTINEL_UP=0
for _ in $(seq 1 50); do
  if SENTINEL_PORT="$SENTINEL_PORT" node "$NODE_WORK/ping-sentinel.mjs" 2>/dev/null; then
    SENTINEL_UP=1
    break
  fi
  sleep 0.1
done
if [ "$SENTINEL_UP" != "1" ]; then
  cat "$WORK/sentinel.log" >&2 || true
  echo "ABORT: sentinel never came up. The negative control cannot run without a" >&2
  echo "verified host listener — an unverified one makes the whole result meaningless." >&2
  exit 1
fi
ok "sentinel verified listening on 0.0.0.0:$SENTINEL_PORT before the run"

# =====================================================================
# 3. Scan, with a sidecar that probes from inside and dumps the rules.
# =====================================================================
echo notfound > "$WORK/found.flag"
(
  deadline=$(( $(date +%s) + 150 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    name="$(docker ps --filter 'name=^mcpg-' --format '{{.Names}}' | head -n1)"
    if [ -n "$name" ]; then
      echo "sidecar: found sandbox container $name" >&2
      echo found > "$WORK/found.flag"

      docker exec "$name" node /target/canary-probe.mjs "$SENTINEL_PORT" \
        > "$WORK/probe.json" 2>"$WORK/probe-stderr.log" \
        || { echo "sidecar: docker exec failed" >&2; cat "$WORK/probe-stderr.log" >&2; }

      # Independent of the errno the probe observed: read the rules that
      # produced it. A `-j REJECT --reject-with icmp-port-unreachable` in
      # the chain text is what makes ECONNREFUSED the CORRECT observation
      # rather than a coincidence, and it is checkable without trusting the
      # probe at all.
      docker run --rm --network host --cap-add=NET_ADMIN --cap-add=NET_RAW \
        palar-net-helper:local sh -c 'iptables -S | grep -E "MCPG|DOCKER-USER" || true' \
        > "$WORK/rules.txt" 2>&1
      docker run --rm --network host --cap-add=NET_ADMIN --cap-add=NET_RAW \
        palar-net-helper:local sh -c 'iptables -S INPUT || true' \
        >> "$WORK/rules.txt" 2>&1
      exit 0
    fi
    sleep 0.1
  done
  echo "sidecar: deadline reached without ever seeing an mcpg- container" >&2
) &
SIDECAR=$!

echo
echo "=== palar live ==="
node dist/cli/index.js live fixtures/vuln-server --execute --json --out "$NODE_WORK/report.json" \
  > "$WORK/live.log" 2>&1
echo "palar live exited $? (1 is EXPECTED once a probe is CONFIRMED)"
wait "$SIDECAR"

# =====================================================================
# 4. Sentinel liveness (AFTER) — the check without which the negative
#    control proves nothing.
# =====================================================================
#
# A dead sentinel yields exactly the same ECONNREFUSED as a working REJECT
# rule. If it died at any point during the run, the probe's "refused" result
# is indistinguishable from success and must NOT be counted as containment.
# Checking only beforehand is insufficient: the window that matters is the
# one the probe ran in, and proving the listener survived to the far side is
# the cheap way to bound it.
echo
echo "=== sentinel liveness (AFTER) ==="
if SENTINEL_PORT="$SENTINEL_PORT" node "$NODE_WORK/ping-sentinel.mjs" 2>/dev/null; then
  ok "sentinel still listening after the run — the refusal was netfilter, not a dead socket"
else
  fail "sentinel DIED during the run. The negative control is VOID: its ECONNREFUSED is what a" \
       "dead listener produces too. Re-run; do not record this as a pass."
fi

# =====================================================================
# 5. ASSERT. Any null is a failure: an indeterminate observation is not a
#    passing one, and "nothing was observed" is not evidence of containment.
# =====================================================================
echo
echo "=== raw values ==="
echo "--- probe ---"
cat "$WORK/probe.json" 2>/dev/null || echo "(none)"
echo "--- rules ---"
cat "$WORK/rules.txt" 2>/dev/null || echo "(none)"

cat > "$WORK/assert.mjs" <<'ASSERT'
import { readFileSync, existsSync } from "node:fs";

const W = process.env.WORK;
const DNS_FAST_MS = Number(process.env.DNS_FAST_MS);
const failures = [];
const fail = (m) => failures.push(m);
const read = (f) => (existsSync(f) ? readFileSync(f, "utf8") : "");

// --- POSITIVE CONTROL -------------------------------------------------
if (!existsSync(`${W}/report.json`)) {
  fail("No live report: the scan did not complete, so every assertion below is indeterminate.");
} else {
  const r = JSON.parse(read(`${W}/report.json`));
  let confirmed = 0;
  for (const live of Object.values(r.live ?? {})) {
    confirmed += (live.probes ?? []).filter((p) => p.status === "confirmed").length;
  }
  if (confirmed < 1) {
    fail(
      `POSITIVE CONTROL: expected >= 1 CONFIRMED probe, got ${confirmed}. Without it the ` +
        `"unreachable" results below prove nothing — broken container networking produces them too.`
    );
  } else {
    console.log(`  ok: positive control — ${confirmed} probe(s) CONFIRMED by oracle callback`);
  }
}

if (read(`${W}/found.flag`).trim() !== "found") {
  fail(
    "Sidecar never found the sandbox container, so NO in-sandbox probe ran. " +
      "'No violations observed' is not containment when nothing was observed."
  );
}

// --- NEGATIVE CONTROL + DNS -------------------------------------------
let probe = null;
try {
  probe = JSON.parse(read(`${W}/probe.json`).trim());
} catch {
  /* reported below */
}

if (!probe) {
  fail("No parseable in-sandbox probe output. Treated as FAILURE, not as 'nothing observed'.");
} else {
  // No field may be indeterminate and pass.
  for (const k of [
    "hostIp",
    "hostListenerReachable",
    "tcpErrorCode",
    "tcpElapsedMs",
    "dnsResolved",
    "dnsErrorCode",
    "dnsElapsedMs",
  ]) {
    if (probe[k] === null || probe[k] === undefined) {
      fail(
        `NULL FIELD: probe.${k} is ${JSON.stringify(probe[k])}. An indeterminate observation is ` +
          `not a passing one. Notes: ${JSON.stringify(probe.notes)}`
      );
    }
  }

  if (probe.hostListenerReachable !== false) {
    fail(
      `NEGATIVE CONTROL: hostListenerReachable === ${JSON.stringify(probe.hostListenerReachable)}, ` +
        `expected false. The sandbox reached a host port with no ACCEPT rule — containment is broken.`
    );
  } else {
    console.log("  ok: negative control — sentinel unreachable from inside the sandbox");
  }

  // REJECT vs DROP, as the probe saw it. Cross-checked against the rule text below.
  if (probe.tcpErrorCode !== "ECONNREFUSED") {
    fail(
      `REJECT SIGNATURE: tcpErrorCode is ${JSON.stringify(probe.tcpErrorCode)}, expected ` +
        `ECONNREFUSED. "TIMEOUT" means the traffic was DROPped rather than REJECTed — a different ` +
        `rule than sandbox.ts claims to install.`
    );
  } else {
    console.log(
      `  ok: refusal is ECONNREFUSED (${Math.round(probe.tcpElapsedMs)}ms) — REJECT, not DROP`
    );
  }

  if (probe.dnsResolved !== false) {
    fail(
      `DNS: dnsResolved === ${JSON.stringify(probe.dnsResolved)}, expected false — the sandbox ` +
        `resolved a name.`
    );
  }
  if (probe.dnsErrorCode !== "EAI_AGAIN") {
    fail(`DNS: dnsErrorCode is ${JSON.stringify(probe.dnsErrorCode)}, expected EAI_AGAIN.`);
  }
  // The timing assertion, which is the one that actually distinguishes a
  // working blackhole from a resolver reaching out and timing out. Both
  // return EAI_AGAIN; only the elapsed time separates them.
  if (!(probe.dnsElapsedMs < DNS_FAST_MS)) {
    fail(
      `DNS TIMING: EAI_AGAIN took ${Math.round(probe.dnsElapsedMs)}ms, expected < ${DNS_FAST_MS}ms. ` +
        `Slow EAI_AGAIN is the documented regression: the code alone cannot distinguish a working ` +
        `blackhole from a resolver genuinely reaching out and timing out — only the time can.`
    );
  } else {
    console.log(`  ok: DNS failed EAI_AGAIN in ${Math.round(probe.dnsElapsedMs)}ms (fast shape)`);
  }
}

// --- RULE TEXT, independent of the errno ------------------------------
const rules = read(`${W}/rules.txt`);
if (!rules.trim()) {
  fail("No iptables rule dump: the REJECT claim would rest on the probe's errno alone.");
} else {
  const accepts = rules.match(/^-A MCPG-[0-9a-f]+ .*-j ACCEPT$/gm) ?? [];
  if (accepts.length !== 1) {
    fail(
      `RULE TEXT: expected exactly 1 ACCEPT in the MCPG chain, found ${accepts.length}. The claim ` +
        `is "permits exactly one destination"; anything else falsifies it. Found: ` +
        `${JSON.stringify(accepts)}`
    );
  } else {
    console.log(`  ok: rule text — one ACCEPT for the oracle's host:port (${accepts[0].trim()})`);
  }

  if (!/^-A MCPG-[0-9a-f]+ -j REJECT --reject-with icmp-port-unreachable$/m.test(rules)) {
    fail(
      "RULE TEXT: no terminal `-j REJECT --reject-with icmp-port-unreachable` in the MCPG chain. " +
        "This is what proves REJECT from the rules rather than inferring it from an errno."
    );
  } else {
    console.log("  ok: rule text — terminal REJECT --reject-with icmp-port-unreachable");
  }

  // Both hooks: DOCKER-USER catches forwarded traffic, INPUT catches
  // host-destined. Desktop needs the second — without it, traffic to the
  // host proxy never traverses DOCKER-USER at all.
  for (const hook of ["DOCKER-USER", "INPUT"]) {
    if (!new RegExp(`^-A ${hook} -s [0-9./]+ -j MCPG-[0-9a-f]+$`, "m").test(rules)) {
      fail(
        `RULE TEXT: no jump from ${hook} into the MCPG chain. On Docker Desktop both hooks are ` +
          `required — DOCKER-USER for forwarded traffic, INPUT for host-destined.`
      );
    } else {
      console.log(`  ok: rule text — ${hook} jumps into the MCPG chain`);
    }
  }
}

if (failures.length) {
  console.error("\n=== FAILURES ===");
  for (const f of failures) console.error("- " + f);
  console.error(
    `\n${failures.length} failure(s). This is a published claim that no longer holds: ` +
      `src/live/sandbox.ts and README.md cite this check, and the project site states it in copy. ` +
      `Retract or correct those before shipping anything else.`
  );
  process.exit(1);
}
console.log("\nAll Docker Desktop containment assertions passed.");
ASSERT

echo
echo "=== assertions ==="
if ! WORK="$NODE_WORK" DNS_FAST_MS="$DNS_FAST_MS" node "$NODE_WORK/assert.mjs"; then
  FAILURES=$((FAILURES + 1))
fi

# =====================================================================
# 6. Teardown leaves nothing behind.
# =====================================================================
echo
echo "=== teardown ==="
LEFT_C="$(docker ps -a --filter 'name=^mcpg-' --format '{{.Names}}' | grep -c . )"
LEFT_N="$(docker network ls --filter 'name=^mcpg-net-' --format '{{.Name}}' | grep -c . )"
LEFT_R="$(docker run --rm --network host --cap-add=NET_ADMIN --cap-add=NET_RAW \
  palar-net-helper:local sh -c 'iptables -S | grep -c MCPG' 2>/dev/null | tr -d '\r' | head -n1)"
LEFT_R="${LEFT_R:-0}"
echo "containers=$LEFT_C networks=$LEFT_N mcpg_rules=$LEFT_R"
if [ "$LEFT_C" = "0" ] && [ "$LEFT_N" = "0" ] && [ "$LEFT_R" = "0" ]; then
  ok "no containers, networks or MCPG-* rules survive teardown"
else
  fail "teardown left containers=$LEFT_C networks=$LEFT_N mcpg_rules=$LEFT_R"
fi

echo
if [ "$FAILURES" -ne 0 ]; then
  echo "RESULT: FAILED ($FAILURES failure group(s)). Do not update the evidence dates."
  exit 1
fi
echo "RESULT: PASSED."
echo "Update the date in src/live/sandbox.ts and README.md to today, with the raw values above."
