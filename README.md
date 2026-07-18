# mcpguard

A defensive, **read-only static analyzer** for local MCP (Model Context
Protocol) tool and server definition files.

mcpguard reads local JSON files and reports on their structure — nothing
else. It makes **no network calls**, generates **no payloads**, and never
executes or imports the content it scans. Findings are reported with
severities, remediation guidance, and an overall 0–100 score with a letter
grade.

## Audit pillars

| Pillar | Rules | What it catches |
| --- | --- | --- |
| `schema-integrity` | IV-001, IV-002 | Execution-adjacent string inputs (`command`, `path`, `url`, `sql`, …) with no `pattern`/`enum`/`format` constraint; sensitive-named tools with no input schema at all |
| `text-sanitization` | TS-001…TS-005 | Hidden Unicode in tool names/descriptions: zero-width characters, bidi override controls, tag characters, stray variation selectors, non-printable controls — reported by code point, never echoed |
| `network-boundaries` | NB-001…NB-004 | Missing egress filtering, filters with no allowlist, and exposed hosts pointing at loopback or private/link-local address space (including the cloud metadata range) |

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

Compares current tool definitions against a saved baseline and prints
color-coded changes (cyan = added, red = removed, yellow = changed).
Exits `1` if anything changed or was removed — suitable as a CI gate
against rug-pull style tool redefinition.

- `--dir <dir...>` — directories to scan
- `--snapshot <file>` — baseline to compare against (default `.mcpguard-snapshot.json`)

> **Windows note:** `--json` output pipes cleanly through Git Bash,
> PowerShell 7+, and cmd, but Windows PowerShell 5.1 re-encodes piped
> native output and can mangle the bytes (e.g. prepend a BOM).

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
  cli/        Command-line entry point (commander): scan, snapshot, drift
  core/       Shared types; auditor (runs rules over discovered files);
              compliance (scoring + Markdown report rendering, with
              suspicious code points escaped); snapshot (canonical
              hashing, baseline load/save, diffing)
  discovery/  Glob-based file discovery and JSON parsing — filesystem
              reads only, with graceful degradation to warnings
  rules/      Rule interfaces and registries; one file per rule
              (input-validation, text-sanitizer, network-bounds)
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
