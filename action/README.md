# MCPGuard GitHub Action

Run [MCPGuard](../README.md) — a defensive, read-only static analyzer for
MCP tool and server definition files — in your repository's CI with a few
lines. The action installs the published `@blithedale/mcpguard` package,
runs `mcpguard scan`, optionally uploads the Markdown report as a workflow
artifact, and fails the step when the severity gate trips.

## Usage

```yaml
name: MCPGuard
on: [push, pull_request]

jobs:
  mcpguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: BlitheBot/MCP/action@v1
        with:
          dir: ./mcp-configs
          fail-on: high
          fail-on-empty: "true"
          out: mcpguard-report.md
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `version` | `latest` | Version of `@blithedale/mcpguard` to install |
| `dir` | `.` | Directory to scan for MCP definition files |
| `fail-on` | *(unset)* | Fail if any finding is at or above this severity (`critical`, `high`, `medium`, `low`, `info`) |
| `fail-on-empty` | `"false"` | Fail when no definition files are discovered — recommended in CI |
| `out` | *(unset)* | Write the Markdown report here and upload it as a workflow artifact |
| `artifact-name` | `mcpguard-report` | Name for the uploaded artifact |

## Outputs

| Output | Description |
| --- | --- |
| `exit-code` | Scan exit code (`0` = passed, `1` = gate tripped) |

## Behavior notes

- The report artifact uploads **even when the scan fails** — the exit code
  is captured, the artifact is uploaded, and only then is the failure
  re-raised, so you always get the report for a failing run.
- Findings are reported with severities, remediation guidance, and a 0–100
  score; see the [main README](../README.md) for the rule catalog.
- The scanner makes no network calls and never executes scanned content.
