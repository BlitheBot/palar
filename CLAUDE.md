# CLAUDE.md

Guidance for Claude working in the PALAR engine repo.

## Competitive positioning: Snyk Agent Scan

Snyk Agent Scan is an inventory tool. It finds every MCP server and skill
across your machine, starts them to read their labels, and ships those labels
to Snyk to be classified as adversarial-looking or not. It never calls a tool,
so it can't tell you whether one is actually exploitable. PALAR points at one
server and tries. When it reports command injection, an out-of-band callback
arrived from inside a sandboxed container. When it reports SSRF, the server
really did fetch an attacker-supplied URL, and a request bearing that probe's
nonce arrived at a listener it should never have been able to reach. Different
question, different answer — if you're securing a fleet, run both.

### Claims discipline for this section

Do not extend the paragraph above to say a PALAR probe reached a real cloud
metadata endpoint. It does not, by design: `buildSsrfPayload()`
(`src/live/probes.ts:144`) returns the oracle callback URL itself, the oracle
is a loopback HTTP listener, and the stdio sandbox restricts egress to that
oracle alone. `src/live/oracle.ts:9-17` and the "Limitations of this pass"
block emitted by `src/live/report.ts:430-437` both disclaim external reach in
PALAR's own output — any competitive copy claiming otherwise is contradicted
by the tool's own report. What the callback proves is that the server fetched
an attacker-supplied URL with no scheme/host allowlist. That is enough; state
that, not more.

The `169.254.169.254` metadata reference in the codebase belongs to the static
rule NB-004 (`network-bounds.ts:131-139`), which flags declared `exposedHosts` in
`mcp.server.json`. That is a declaration check, not a confirmed reach — keep
the two separate when writing about coverage.

### Source of the Snyk claims

Verified 2026-08-17 against primary sources only (`github.com/snyk/agent-scan`
main at `version = "0.6.0"`; PyPI latest `0.5.17`), not blog posts or summaries:

- Live execution is enumeration-only: `mcp_client.py:133` spawns the stdio
  server, `_check_server_pass` (`:154`) calls `initialize()`, `list_prompts()`,
  `list_resources()`, `list_tools()`. There is no `call_tool` anywhere in
  `src/` — no tool is ever invoked and no input is ever crafted.
- Detection is server-side: the collected signature is POSTed to
  `api.snyk.io/hidden/mcp-scan/analysis-machine` (`verify_api.py:449`).
  `SNYK_TOKEN` is mandatory; without it a scan exits 1 with no findings.
  `detect-secrets` is used only in `redact.py` for pre-transmission redaction,
  not for detection.
- No drift or pinning: there is no `whitelist` command (only a `0.1.4.6`
  changelog line inherited from Invariant Labs' `mcp-scan`), and the
  `--storage-file` flag (`cli.py:163`) is parsed but never read anywhere.
- No sandboxing: it runs untrusted server commands on the host and documents
  that the user should sandbox the scanner. Its protection is a y/n consent
  prompt, bypassed by `--dangerously-run-mcp-servers`.
- Output is console plus `--json` on stdout. No report file, no SARIF, no
  signed artifact.

Re-verify before reusing these in anything outward-facing; v0.6 was unpublished
on PyPI as of the date above, so `@latest` still resolved to the 0.5.x line.

## Shipped: distinguishing an environmental failure from a target refusal

`rejected` used to span two things a reader hears differently: the handler
ran and refused the payload, and the handler could not run at all.
Playwright's two probes were counted `rejected` when Chromium was simply
absent from the container.

This is now separated by a **benign control call** (`live/control.ts`):
same tool, schema-valid benign arguments, no payload, sent only when a
probe would otherwise read `rejected`, memoized per tool, seeded from the
poisoning check when that already made the identical call. If the control
errors too, the probe reads `inconclusive` (`live/status.ts`), which is
excluded from coverage (`live/coverage.ts`) and escalates nothing.

The gate: an annotation may only ever SUBTRACT permission. `destructiveHint:
true` vetoes; a *safety* claim grants nothing, because a safety claim is
what a hostile server would write. Permission comes from the sandbox, so
SSE targets are refused outright, as are tools whose names match palar's
own destructive-verb list. `runPoisoningCheck` is gated by the same rule —
it predates the gate and would otherwise have been a hole in it.

Measured cost: the control call skips the oracle wait entirely (the probe
phase is ~99% callback timeout — 12 probes x 4s ~ the 48-49s measured
phase), so its marginal cost is one bare round trip: median 6ms, max 70ms
across 15 calls against `vuln-server` in the real sandbox; 5-7ms observed
end-to-end. Bounded by `--control-timeout-ms` (defaults to
`--callback-timeout-ms`) because the real risk is a tool that BLOCKS, not
one that is slow.

### Open: SSE targets already receive payloads

Gating the benign control for SSE while the *payload* still goes out is not
a defensible line, and it is recorded as a known incoherence in
`live/control.ts` rather than papered over.

`liveScan.ts`'s probe loop has **no transport branch**. `isStdio` is
consulted in exactly four places — the definition, the result label, the
stdio-only pre-flight, and sandbox creation — and none of them gate
probing. So an SSE target receives the full injection payload set
(`buildCommandInjectionPayload` / `buildSsrfPayload`) over the network,
unsandboxed, to a remote server. `--execute`'s warning text does say SSE
targets are "unaffected" by the sandboxing, which is true but reads as
reassurance about isolation rather than as notice that payloads still go
out.

Deciding what probing an SSE target should do is a separate change with a
separate blast radius, and it was deliberately not made alongside the
control call.
