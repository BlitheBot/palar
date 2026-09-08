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

---

## Working agreement

*How to make changes in this repo. This section does not restate the
outward-facing claims discipline in **Competitive positioning → Claims
discipline for this section** and **Source of the Snyk claims** above —
those own that topic and win where they apply.*

### The loop

Every non-trivial change follows: **plan → failing test → implement → fresh-context review → verify**.

Trivial means: typo, comment, log-message wording, single-line config value. Everything
else goes through the loop. If you're unsure which side something falls on, it's not trivial.

### 1. Plan first

Before writing implementation code for anything spanning more than one file or one
function, write the plan to `docs/plans/<short-name>.plan.md` and stop.

The plan states:
- What changes, file by file
- What could break that currently works
- How we'll know it worked (the specific test or command)
- What you're deliberately NOT doing

Then wait for approval. Do not start implementing because the plan "seems obviously right."

### 2. Failing test before fix

For bug fixes: reproduce with a test that fails for the right reason, and show me the
failure output. A test that passes before your change proves nothing about your change.

For new behavior: write the test, watch it fail, then implement.

Paste real output. Never describe a test result you didn't run.

### 3. Implement narrowly

Change only what the plan said you'd change. If you discover the plan was wrong mid-way,
stop and say so rather than silently expanding scope. Unrelated cleanup you spot along
the way goes in a note at the end, not in this diff.

### 4. Review from a fresh reading

Before declaring done, re-read the diff as if you didn't write it. Look for:
- Cases the tests don't cover
- Silent failures (swallowed exceptions, unchecked returns, default-on-error)
- String/enum mismatches between call sites
- State that's in memory only and dies on restart

State findings even when they mean more work. "I reviewed it and it's fine" with no
specifics means you didn't review it.

### 5. Verify

Run the actual commands. Build, lint, types, tests. Paste output.

If something is unverified, say the word "unverified" next to it. Do not summarize a
session as clean when part of it was reasoned about rather than run.

### Honesty rules

- Never report a command as run if it wasn't run.
- Never claim a test passes without the output.
- When you don't know, say you don't know, then go find out.
- If you broke something earlier in the session, say so plainly in the summary.

### Git

- Commit freely on feature branches.
- **Do not push** anything touching live-money paths, credentials, or deploy config
  without explicit sign-off in this session.
- `git status` before every commit; confirm nothing unrelated got swept in.
- One logical change per commit. Commit message says why, not what.

### Project-specific

<!-- Edit per repo. Examples of what belongs here: -->
- Test command: `npm test` (package.json `scripts.test`: `tsc -p tsconfig.json && node --test "dist/**/*.test.js"`; also run as `npm test` in `.github/workflows/ci.yml`)
- Lint/typecheck command: `npm run typecheck` (package.json `scripts.typecheck`: `tsc --noEmit`). No lint command found — no `lint` script in package.json, no ESLint/Prettier/Biome config in the repo, and no lint step in any workflow under `.github/workflows/`.
- Build command: `npm run build` (package.json `scripts.build`: `tsc`; also run as `npm run build` in `.github/workflows/ci.yml`)
- Package manager: `npm` — use it, don't hand-edit lockfiles or manifests (`package-lock.json` at repo root; `.github/workflows/ci.yml` runs `npm ci` with `cache: npm`)
- Paths that require extra care before editing:
  - `src/live/sandbox.ts` — the sandbox / egress-firewall install path (`buildFirewallScript()` ~L308, `installFirewall()` ~L434). A wrong rule here silently widens container egress; `.github/workflows/canary.yml` is the only end-to-end check that the firewall actually contains.
  - `src/live/oracle.ts` — the callback oracle (loopback HTTP listener). A received callback is the sole proof a probe is real; **Claims discipline for this section** above pins what it does and does not establish.
  - `src/live/escalate.ts` — the one place in the codebase that rewrites a `ruleId` (IV-001 → `IV-101` on a confirmed callback, ~L62 / L96–103). It also moves severity and score before anything renders or gates, so a mistake changes `--fail-on` and `--json` output, not just display.
  - `src/core/compliance.ts` — scoring and grade computation (`computeScore`, the severity and confidence weight tables). `escalate.ts` recomputes through it; a weight change moves every grade.
  - `fixtures/vuln-server/` — the palar-site transcript is generated from a real run of this fixture (see `fixtures/contradiction-server/README.md` and `CHANGELOG.md`), so **any** change to its tools, schemas, `mcp.*.json`, or `src/index.js` breaks that transcript. Two obligations, both required: (1) note the fixture change in the commit message here, and (2) regenerate on the site side before the site's next deploy — otherwise the published page goes silently stale. The generator lives in the site repo, not this one: `C:\Users\mjshi\OneDrive\Desktop\Palar\PALAR\PALAR`. Regeneration there is manual — that repo has no generator script (no `package.json`, `Makefile`, or `scripts/`); the transcript is real terminal output pasted into its `index.html`, and the findings/score it must agree with are pinned in that repo's `CLAUDE.md` §6.
  - Already delicate, already covered above — don't re-document, just tread carefully: `src/live/control.ts` (the permission gate — see **Shipped: distinguishing an environmental failure from a target refusal**), and `src/live/probes.ts` / `src/rules/network-bounds.ts` (see **Claims discipline for this section**).
