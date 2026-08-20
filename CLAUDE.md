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
(`src/live/probes.ts:126`) returns the oracle callback URL itself, the oracle
is a loopback HTTP listener, and the stdio sandbox restricts egress to that
oracle alone. `src/live/oracle.ts:9-17` and the "Limitations of this pass"
block emitted by `src/live/report.ts:219-226` both disclaim external reach in
PALAR's own output — any competitive copy claiming otherwise is contradicted
by the tool's own report. What the callback proves is that the server fetched
an attacker-supplied URL with no scheme/host allowlist. That is enough; state
that, not more.

The `169.254.169.254` metadata reference in the codebase belongs to the static
rule `network-bounds.ts:122`, which flags declared `exposedHosts` in
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
