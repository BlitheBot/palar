# palar

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
  inferring it from schema shape. This mode is **not** read-only: stdio
  targets run inside an ephemeral, network-restricted Docker container
  (Docker is required, with no unsandboxed fallback) — read the "Live
  scanning" section for exactly what that does and doesn't cover before
  using it against anything you don't fully trust.

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
package makes the `palar` binary available directly.

## Usage

### `palar scan [paths...]`

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
  palar scan --dir ./mcp-configs --fail-on high --fail-on-empty
  ```

  Use both in CI: `--fail-on` catches dangerous definitions, while
  `--fail-on-empty` catches a moved or misconfigured scan path — which
  should fail loudly, not silently pass as "clean." Pair with
  `palar drift` to also catch individual definitions disappearing
  between runs.

### `palar snapshot`

Records a baseline of SHA-256 hashes (key-order independent) of every
discovered tool definition, for later drift detection.

- `--dir <dir...>` — directories to scan
- `--out <file>` — snapshot file to write (default `.palar-snapshot.json`)

### `palar drift`

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
redefinition. Baselines from older palar versions (hash-only) still
diff, but degrade to plain `changed` entries without semantic detail —
re-run `palar snapshot` to upgrade the baseline.

- `--dir <dir...>` — directories to scan
- `--snapshot <file>` — baseline to compare against (default `.palar-snapshot.json`)

> **Windows note:** `--json` output pipes cleanly through Git Bash,
> PowerShell 7+, and cmd, but Windows PowerShell 5.1 re-encodes piped
> native output and can mangle the bytes (e.g. prepend a BOM).

## Live scanning (`palar live`) — experimental

Unlike `scan`, this command actually runs the target: it spawns a
discovered server's declared `command`/`args` as a real child process over
stdio (or connects over SSE if the server config declares
`"transport": "sse"` and a `"url"`), performs the real MCP handshake, calls
`listTools()` against the live process, and — for tools with an
unconstrained execution-adjacent field (the same detection IV-001 uses) —
sends a real crafted payload through a real `callTool()` call.

**Confirmation is via an out-of-band callback, not response text.**
palar starts a local HTTP listener for the duration of the scan, embeds
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
palar live fixtures/vuln-server --execute
```

`--execute` is required — `live` refuses to run without it, since (unlike
`scan`) it has real side effects. Other flags: `--timeout-ms` (hard ceiling
for the whole scan per server, default 60000), `--connect-timeout-ms` (how
long to wait for a target's connect/handshake, default 30000 — a stdio
target has to start a container and then get itself to the point of
answering, measured at 8–10s for the `vuln-server` fixture on Docker
Desktop; `--timeout-ms` bounds the whole scan, so keep it the larger of the
two or it preempts this one), `--callback-timeout-ms`,
`--oracle-host` (default `127.0.0.1`, SSE targets only — see below),
`--json`, `--out`. Exits `1` if any finding was CONFIRMED.

### Sandboxing: stdio targets run in a Docker container

For stdio targets (the only case that spawns anything), `live` runs the
target's declared `command`/`args` inside an ephemeral Docker container
instead of directly on this host. **Docker is required — there is no
unsandboxed fallback**; if `docker version` fails, `live` fails closed with
a clear error rather than falling back to running the target on the host.
Per scan:

- a fresh bridge network is created and torn down afterward;
- the container is `--read-only` with a `noexec` tmpfs at `/tmp`, every
  Linux capability dropped (`--cap-drop=ALL`), `no-new-privileges`, and
  `--pids-limit`/`--memory`/`--cpus` resource limits;
- the target's own directory is bind-mounted read-only at `/target` —
  **not** palar's own source, and nothing above the target's directory;
  the target's own `node_modules` must exist there already (palar
  doesn't install dependencies on your behalf — see
  `fixtures/vuln-server/README.md` for what that means for the fixture);
  palar builds the container's declared env explicitly (`src/live/env.ts`
  / `src/live/sandbox.ts`) from exactly `mcp.server.json`'s own `"env"`
  field — no ambient host environment reaches the container;
- egress is restricted to exactly this scan's own oracle callback
  listener: a per-scan `iptables` chain (`ACCEPT` to the oracle, `REJECT`
  everything else) is hooked in from **two** places, because they cover
  disjoint traffic — Docker's `DOCKER-USER` chain, which only sees
  *forwarded* traffic (the container reaching the outside world or another
  container), and `INPUT`, scoped `-s <this scan's subnet>`, which sees
  host-*destined* traffic that terminates on the host's own stack rather
  than being forwarded. Without the `INPUT` hook, services listening on the
  host itself stay reachable from the sandbox at the bridge gateway
  address. Both jumps and the chain are removed on teardown, alongside the
  container and network;
- **the sandbox has no DNS resolver at all**: its only nameserver points at
  container-local loopback, where nothing listens, so any hostname lookup
  fails immediately. Nothing about scanning an MCP server requires
  resolving arbitrary hostnames, and Docker's own resolver otherwise keeps
  answering external queries straight through the egress rules above. The
  oracle callback is unaffected — `host.docker.internal` is pinned in the
  container's `/etc/hosts`, which needs no resolver;
- on startup, `live` sweeps up sandbox state orphaned by an earlier run
  that never reached teardown (a crash, a kill, a Ctrl-C): leftover
  `mcpg-*` containers and networks and `MCPG-*` chains with their
  `DOCKER-USER`/`INPUT` jumps. It reports what it reclaimed rather than
  cleaning up silently. This matters because a `docker run` client killed
  by Ctrl-C does *not* stop the container it started, so an orphan can
  otherwise outlive the scan indefinitely.

The oracle binds to whichever address is actually reachable on the detected
Docker backend (host loopback on Docker Desktop; that scan's bridge network
gateway on native Linux Engine, where a loopback-bound listener isn't
reachable from inside a container), so `--oracle-host` only affects the SSE
case.

**What this is, plainly stated:** Docker + `iptables` container isolation,
not a VM and not gVisor — a kernel-level container escape is not mitigated.
Named gaps, not silently deferred:

- the `DOCKER-USER` and `INPUT` chains are shared, host-global state;
  concurrent `palar live` invocations against the same Docker daemon
  aren't supported yet (the per-scan chain limits this to two shared
  jump-rule inserts/deletes per scan, but that's still a race, not
  eliminated). The startup sweep sharpens this: it can't tell a crashed
  run's leftovers from a concurrent run's live state, so a second
  invocation will reclaim the first's container and chains;
- **verified against Docker Desktop (Windows/WSL2)** — that's the backend
  the containment claims were actually measured on, by dumping live
  netfilter state mid-scan and probing the sandbox from a second shell
  (host-namespace listener unreachable, DNS resolution failing, oracle
  callback still landing). The native Linux Docker Engine path is
  implemented from documented Docker/netfilter behavior but is **not**
  verified end-to-end; nftables-only hosts, where the `iptables` shim may
  not apply these rules as written, are untested. Re-run those checks
  before trusting either;
- the oracle callback listener has no rate-limiting or body-size cap;
- resource limits are best-effort hardening against fork-bombing/resource
  exhaustion, not a hard guarantee on par with a VM boundary;
- **SSE targets are unaffected** — there's no local process to sandbox for
  an already-running remote server; the callback-oracle scope limitation
  below still applies to both.

### What the oracle proves, and what it doesn't

- The oracle is a **local HTTP listener**, not external DNS/HTTP
  collaborator infrastructure (interactsh-style). It proves command
  injection or SSRF that can reach the scanning host's own network. It does
  **not** prove reach to genuine external infrastructure — e.g. a real
  cloud metadata endpoint that's only reachable from inside a target's own
  VPC. Building that is separate, larger work.
- Tool-poisoning / prompt-injection findings (hidden Unicode instructions in
  a description) have **no oracle-style confirmation** in this mode: the
  payload targets an LLM's judgment, and palar's live scanner isn't one.
  What `live` adds for this class is cross-checking that the poisoned text
  is genuinely served by the running process (`listTools()`), not just
  present in a JSON file that might be stale.

## GitHub Action

Add Palar to any repository's CI without installing anything — see
[`action/README.md`](action/README.md) for full input docs:

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: BlitheBot/palar/action@v1
    with:
      dir: ./mcp-configs
      fail-on: high
      fail-on-empty: "true"
```

## Configuration

All commands accept `--config <path>`, and a `.palarrc.json` in the
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

palar finds definitions by naming convention, searching each given path
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
              listener), sandbox (per-scan Docker container + network +
              iptables egress control for stdio targets), connector (real
              stdio/SSE MCP client via @modelcontextprotocol/sdk), probes
              (payload classification and construction, reusing
              rules/input-validation.ts's keyword matching), liveScan
              (orchestrator), report (CONFIRMED / ATTEMPTED-UNCONFIRMED /
              STATIC-ONLY rendering)
docker/       Dockerfiles for the `live` sandbox: target-runtime (minimal
              node:20-slim the target's own command runs in) and net-helper
              (alpine + iptables, used only to install/remove the per-scan
              DOCKER-USER and INPUT firewall rules and to sweep up ones
              orphaned by a crashed run)
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
