# Palar GitHub Action

Run [Palar](../README.md) — a defensive, read-only static analyzer for
MCP tool and server definition files — in your repository's CI with a few
lines. The action installs the published package, runs a scan, optionally
uploads the Markdown report as a workflow artifact, and fails the step when
the severity gate trips.

## Usage

```yaml
name: Palar
on: [push, pull_request]

jobs:
  palar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: BlitheBot/palar/action@v1
        with:
          dir: ./mcp-configs
          fail-on: high
          fail-on-empty: "true"
          out: palar-report.md
```

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `version` | `"0.4.0"` | Version of `palar` to install — pinned so the gate's verdict cannot change without a change in your repo; set it to `^0.4.0` or `latest` to float. Ignored when `binary` is set |
| `binary` | *(unset)* | Run an already-built palar executable instead of installing from npm. Leave unset — see below |
| `dir` | `.` | Directory to scan for MCP definition files |
| `fail-on` | *(unset)* | Fail if any finding is at or above this severity (`critical`, `high`, `medium`, `low`, `info`) |
| `fail-on-empty` | `"false"` | Fail when no definition files are discovered — recommended in CI |
| `out` | *(unset)* | Write the Markdown report here and upload it as a workflow artifact |
| `artifact-name` | `palar-report` | Name for the uploaded artifact |

## Outputs

| Output | Description |
| --- | --- |
| `exit-code` | Scan exit code (`0` = passed, `1` = gate tripped) |

## Behavior notes

- `binary` exists for this repository's own self-test
  (`.github/workflows/action-test.yml`), which has to scan with the build
  from the checkout rather than the last published release — otherwise a
  green self-test would say nothing about the code it is meant to be
  testing. When it is set the npm install is skipped entirely. Consumers
  should leave it unset and take the published package.
- The report artifact uploads **even when the scan fails** — the exit code
  is captured, the artifact is uploaded, and only then is the failure
  re-raised, so you always get the report for a failing run.
- Findings are reported with severities, remediation guidance, and a 0–100
  score; see the [main README](../README.md) for the rule catalog.
- The scanner makes no network calls and never executes scanned content.
