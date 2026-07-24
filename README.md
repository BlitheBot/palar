# mcpguard

A defensive analyzer for local MCP (Model Context Protocol) tool and server
definition files, with two distinct modes:

- **`scan` / `snapshot` / `drift`** (the original engine) — **read-only
  static analysis**. These commands read local JSON files and report on
  their structure only. They make **no network calls**, generate **no
  payloads**, and never execute or import the content they scan. Findings
  are reported with severities, remediation guidance, and an overall 0–100
  score with a letter grade.
- **`live`** (new, experimental — see below) — actually spawns/connects to
  the target server and sends it crafted input over a real MCP connection,
  confirming exploitability via an out-of-band callback rather than
  inferring it from schema shape. This mode is **not** read-only and **not**
  sandboxed — read the "Live scanning" section before using it against
  anything you don't fully trust.

## Audit pillars

| Pillar | Rules | What it catches |
| --- | --- | --- |
| `schema-integrity` | IV-001, IV-002 | Execution-adjacent string inputs (`command`, `path`, `url`, `sql`, …) with no `pattern`/`enum`/`format` constraint; sensitive-named tools with no input schema at all |
| `text-sanitization` | TS-001…TS-005 | Hidden Unicode in tool names/descriptions: zero-width characters, bidi override controls, tag characters, stray variation selectors, non-printable controls — reported by code point, never echoed |
| `network-boundaries` | NB-001…NB-004 | Missing egress filtering, filters with no allowlist, and exposed hosts pointing at loopback or private/link-local address space (including the cloud metadata range) |
| `credential-exposure` | CR-001…CR-006 | Hardcoded credentials anywhere in a definition file's string values: AWS access keys, API key/token/secret literals, OpenAI-style keys, Slack tokens, bearer tokens, and PEM private-key headers — matched secrets are redacted to `first4...last2` in the report |

## Install & build

```sh
npm install
npm run build     # compile to dist/
npm test          # compile + run the test suite (node:test, no extra deps)
```

Run from source during development with `npm run dev -- <command>`, or via
the built CLI with `node dist/cli/index.js <command>`. Installing the
package makes the `mcpguard` binary available directly.

## Usage

### `mcpguard scan [paths...]`

Discovers definition files, runs every rule, and prints a Markdown audit
report plus a colored one-line score summary.

- `--dir <dir...>` — additional directories to scan (merged with positional paths; defaults to the current directory)
- `--json` — print the raw `AuditResult` as JSON on stdout (status goes to stderr, so piping stays clean)
- `--out <file>` — write the report to a file instead of stdout
- `--fail-on <severity>` — exit `1` if any finding is at or above the given
  severity (`critical`, `high`, `medium`, `low`, or `info`), in every output
  mode. A red status line states what triggered the failure. Without
  `--fail-on` (or when no finding meets the threshold), `scan` exits `0`
  regardless of findings.
- `--fail-on-empty` — exit `1` when no definition files are discovered at
  all (off by default: normally an empty scan exits `0`, since there is
  nothing to evaluate).

  Together these make `scan` usable as a CI gate:

  ```sh
  mcpguard scan --dir ./mcp-configs --fail-on high --fail-on-empty
  ```

  Use both in CI: `--fail-on` catches dangerous definitions, while
  `--fail-on-empty` catches a moved or misconfigured scan path — which
  should fail loudly, not silently pass as "clean." Pair with
  `mcpguard drift` to also catch individual definitions disappearing
  between runs.

### `mcpguard snapshot`

Records a baseline of SHA-256 hashes (key-order independent) of every
discovered tool definition, for later drift detection.

- `--dir <dir...>` — directories to scan
- `--out <file>` — snapshot file to write (default `.mcpguard-snapshot.json`)

### `mcpguard drift`

Compares current tool definitions against a saved baseline. Snapshots
store a bounded structural summary per tool (property paths with scalar
constraints, enum *counts*, and description *length* — never raw enum
values or description text), so drift reports *what* changed, not just
that a hash differs. Each specific change is classified as a
**tightening** (e.g. pattern added), a **loosening** (e.g. pattern
removed, enum expanded, required flag dropped, max bound raised), or
**neutral** (e.g. a description reword). A changed tool with any
loosening change is reported as `regressed` — a security regression —
with a reason line, e.g.:

```
regressed: runner — security regression: pattern removed from parameter "command"
  [loosening] pattern removed from parameter "command"
  [neutral] description length changed from 30 to 37 characters
added: new_tool
```

Exits `1` if anything changed, regressed, or was removed (additions alone
exit `0`) — suitable as a CI gate against rug-pull style tool
redefinition. Baselines from older mcpguard versions (hash-only) still
diff, but degrade to plain `changed` entries without semantic detail —
re-run `mcpguard snapshot` to upgrade the baseline.

- `--dir <dir...>` — directories to scan
- `--snapshot <file>` — baseline to compare against (default `.mcpguard-snapshot.json`)

> **Windows note:** `--json` output pipes cleanly through Git Bash,
> PowerShell 7+, and cmd, but Windows PowerShell 5.1 re-encodes piped
> native output and can mangle the bytes (e.g. prepend a BOM).

## Live scanning (`mcpguard live`) — experimental

Unlike `scan`, this command actually runs the target: it spawns a
discovered server's declared `command`/`args` as a real child process over
stdio (or connects over SSE if the server config declares
`"transport": "sse"` and a `"url"`), performs the real MCP handshake, calls
`listTools()` against the live process, and — for tools with an
unconstrained execution-adjacent field (the same detection IV-001 uses) —
sends a real crafted payload through a real `callTool()` call.

**Confirmation is via an out-of-band callback, not response text.**
mcpguard starts a local HTTP listener for the duration of the scan, embeds
a unique per-probe nonce in each payload (a callback URL for SSRF-style
fields, a shell-metacharacter-appended callback for command-injection-style
fields), and waits up to `--callback-timeout-ms` (default 4000ms) for a
request bearing that nonce to arrive. A received callback is reported
**CONFIRMED**; no callback is reported **ATTEMPTED — UNCONFIRMED**, never
silently treated as "safe" (egress could be blocked, the payload could have
failed for an unrelated reason, etc.). Findings with no live equivalent yet
(credential scanning, network-posture config, schema meta-validation,
description hygiene) are reported **STATIC-ONLY**. These three categories
are always kept visibly separate in the report — never flattened into one
list.

```sh
mcpguard live fixtures/vuln-server --execute
```

`--execute` is required — `live` refuses to run without it, since (unlike
`scan`) it has real side effects. Other flags: `--timeout-ms` (hard ceiling
for the whole scan per server, default 30000), `--callback-timeout-ms`,
`--oracle-host` (default `127.0.0.1`), `--json`, `--out`. Exits `1` if any
finding was CONFIRMED.

### What this proves, and what it doesn't

- The oracle is a **local loopback HTTP listener**, not external DNS/HTTP
  collaborator infrastructure (interactsh-style). It proves command
  injection or SSRF that can reach the scanning host's own network. It does
  **not** prove reach to genuine external infrastructure — e.g. a real
  cloud metadata endpoint that's only reachable from inside a target's own
  VPC. Building that is separate, larger work.
- Tool-poisoning / prompt-injection findings (hidden Unicode instructions in
  a description) have **no oracle-style confirmation** in this mode: the
  payload targets an LLM's judgment, and mcpguard's live scanner isn't one.
  What `live` adds for this class is cross-checking that the poisoned text
  is genuinely served by the running process (`listTools()`), not just
  present in a JSON file that might be stale.
- **There is no sandboxing.** The target runs directly on this machine for
  the duration of the scan — no container, no gVisor, no filesystem or
  network isolation. mcpguard builds the child's environment explicitly
  (never spreading its own `process.env` into the target — see
  `src/live/env.ts`), enforces a hard overall timeout, and unconditionally
  kills the child process afterward — but none of that is a security
  boundary. **Do not run `mcpguard live` against a third party's server or
  any client's infrastructure until real isolation (containers or gVisor)
  exists.** That is the next major piece of work, not an indefinitely
  deferred one.

## GitHub Action

Add MCPGuard to any repository's CI without installing anything — see
[`action/README.md`](action/README.md) for full input docs:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: BlitheBot/MCP/action@v1
    with:
      dir: ./mcp-configs
      fail-on: high
      fail-on-empty: "true"
```

## Configuration

All commands accept `--config <path>`, and a `.mcpguardrc.json` in the
working directory is picked up automatically. With no config present,
behavior is identical to the built-in defaults. A malformed config is a
hard error, never silently ignored. Every field is optional except
`configVersion` (must be `1` — future shape changes will bump it rather
than silently breaking existing files).

```json
{
  "configVersion": 1,
  "limits": {
    "maxFileSize": 10485760,
    "maxNestingDepth": 50,
    "maxSchemaNodes": 5000
  },
  "sensitiveKeywords": ["command", "cmd", "path", "url", "sql", "deploy_target"],
  "unicodeCategories": {
    "zeroWidth": ["200B-200D", "2060", "FEFF"],
    "bidi": ["202A-202E", "2066-2069"],
    "tagChars": ["E0000-E007F"],
    "variationSelectors": ["FE00-FE0F"],
    "controlChars": ["0000-0008", "000B-000C", "000E-001F", "007F-009F"]
  },
  "network": {
    "loopbackHosts": ["localhost", "0.0.0.0", "::1"],
    "loopbackPatterns": ["^127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"],
    "privateSubnetPatterns": ["^10\\.", "^192\\.168\\."]
  },
  "severityOverrides": {
    "IV-001": "medium"
  },
  "description": {
    "maxLength": 1000,
    "injectionKeywords": ["ignore previous instructions", "system prompt"]
  }
}
```

- `limits` — the scanner-hardening caps (also settable per run via
  `--max-file-size`, `--max-nesting-depth`, `--max-schema-nodes`, which
  win over the file).
- `sensitiveKeywords` — identifier segments input-validation treats as
  execution-adjacent; replaces the default list.
- `unicodeCategories` — hex code points/ranges per text-sanitizer
  category; each specified category replaces its default, unspecified
  categories keep theirs.
- `network` — exact loopback host names plus regex sources for loopback
  and private-subnet host matching in network-bounds.
- `severityOverrides` — per-ruleId severity replacement (e.g. downgrade
  `IV-001` to `medium`); affects both the report and the score.
- `description` — the description-hygiene rule's length threshold and
  injection-phrase heuristic list (replaces the default list).

## File discovery

mcpguard finds definitions by naming convention, searching each given path
recursively:

- **Tool definitions:** `mcp.tools.json`, `tools/*.json`, `*.mcp-tools.json`
- **Server configs:** `mcp.server.json`, `mcp.config.json`, `*.mcp-server.json`

`node_modules/`, `dist/`, `.git/`, and `examples/` directories are always
skipped, and symlinks are not followed. A file may contain a single
definition object or an array of them. Malformed or unreadable files are
skipped with a warning (surfaced in the report and `--json` output), as are
entries missing a string `name`. Duplicate tool names and files matching
both a tool and a server pattern also produce warnings rather than failing
the scan.

## Architecture

```
src/
  cli/        Command-line entry point (commander): scan, snapshot, drift, live
  core/       Shared types; auditor (runs rules over discovered files);
              compliance (scoring + Markdown report rendering, with
              suspicious code points escaped); snapshot (canonical
              hashing, baseline load/save, diffing)
  discovery/  Glob-based file discovery and JSON parsing — filesystem
              reads only, with graceful degradation to warnings
  rules/      Rule interfaces and registries; one file per rule
              (input-validation, text-sanitizer, network-bounds)
  live/       The `live` command's engine: oracle (local HTTP callback
              listener), connector (real stdio/SSE MCP client via
              @modelcontextprotocol/sdk), probes (payload classification
              and construction, reusing rules/input-validation.ts's
              keyword matching), liveScan (orchestrator), report
              (CONFIRMED / ATTEMPTED-UNCONFIRMED / STATIC-ONLY rendering)
```

Rules implement a small `check(definition, context) → Finding[]` interface
and are registered in `src/rules/index.ts`; the auditor iterates the
registries, so adding a rule is one new file plus one registry entry.
Tests live alongside their subjects as `src/**/*.test.ts` and run on
Node's built-in test runner.

## Scoring

Scores start at 100 and subtract severity weights (critical 50, high 30,
medium 15, low 5, info 0), dampened by 1/√n for repeated findings from the
same rule so one noisy rule doesn't dominate. Grades: A ≥ 90, B ≥ 75,
C ≥ 60, D ≥ 40, otherwise F.
