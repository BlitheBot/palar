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

## Deferred: distinguishing an environmental failure from a target refusal

`rejected` currently spans two things a reader hears differently: the handler
ran and refused the payload, and the handler could not run at all. Playwright's
two probes were counted `rejected` when Chromium was simply absent from the
container — the tool never ran, no request was attempted, and `rejected` reads
as reassurance.

From the tool result alone this is not separable. MCP gives one `isError`
boolean and a free-form text body; there is no structured error class, and
`status.ts` argues at length against pattern-matching the text.

The instrument that DOES separate them without reading error strings is a
**benign control call**: the same tool, schema-valid benign arguments, no
payload — machinery that already exists in `benignValueFor()` and
`runPoisoningCheck()`. If the control errors too, the probe's error was not a
refusal *of the payload*. Report that as a distinct status, `inconclusive`.

Deliberately not implemented yet, and the reasons are the design work still
owed rather than an objection:

- It doubles tool calls against a live target.
- A benign call to a destructive tool is still a real side effect. `delete_file`
  with schema-valid filler is not a no-op, and the control must not be sent
  blindly to every tool.
- It establishes only that the payload was not the cause — not *why*. A missing
  browser and a tool that refuses everything look identical, though arguably
  both deserve the same non-reassuring status.

Do not ship this as a quick follow-on to the probe loop. Decide the
side-effect gate first (which tools may receive a control call at all), then
measure it against playwright, where the known-correct answer is that both
probes should stop reading as refusals.
