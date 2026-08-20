# Changelog

All notable changes to `palar` are documented here.

This project is pre-1.0. Under `0.x`, minor releases may change behaviour;
the "Behaviour changes" section of each entry is the part to read before
upgrading a CI gate.

## 0.3.0

### Behaviour changes

Two changes are visible to an existing CI job **without any flag changing**.
Neither is an API break, and both are the intended fix rather than a side
effect — but a pipeline that was green on 0.2.0 can read differently on
0.3.0.

- **Scores move materially, because findings are now weighted by
  confidence.** A finding's penalty is its severity weight scaled by how
  much palar actually established (see below), so results dominated by
  unverified static hypotheses score far higher than before, and confirmed
  findings score lower. Measured across the sample: `server-filesystem`
  20/F → 80/B, `playwright-mcp` 74/C → 94/A, `server-memory` 85/B → 96/A,
  `desktop-commander` 4/F → 72/C on `scan` and 0/F → 11/F on `live`. The
  `vuln-server` fixture stays 0/F.

  **`--fail-on` is unaffected** — it gates on severity, and no severity
  weight changed. A gate that asserts a **numeric score threshold** will see
  different numbers and should be re-baselined against a 0.3.0 run.

- **`palar live --json` omits `score` entirely when no target was reached,
  and `live` exits `2` in more cases.** The document now carries an
  `outcome` field (`probed` / `partial` / `never-reached`). When nothing was
  reached, the static findings are still emitted but no grade is — a run
  that never spoke to a running server has no verdict to summarise, and a
  CI job reads a grade as the answer to "did this pass?". Exit `2` now
  covers every way of examining nothing: no target reached, every target
  reached exposing zero tools, or every probe NOT TESTED. A script reading
  `.static.score` unconditionally will now see `undefined` in exactly the
  case where the old `85/B` was wrong.

  Note `live`'s exit `1` (something was CONFIRMED) and `scan`'s exit `1`
  (reached, zero tools) mean different things. `live` folds its own
  zero-tools case into `2` rather than matching `scan`'s numbering, so a
  coverage gap is never reported as a confirmation.

### Added

- **Working command-injection oracle.** A confirmed finding now rests on an
  out-of-band callback carrying that probe's unique nonce, arriving at
  palar's listener from inside the sandboxed container. The runtime image
  gained `curl` (the callback binary was missing, so successful injections
  reported UNCONFIRMED) and the host-platform payload branch was dropped.

- **Confidence scoring.** Every finding carries a required `confidence`
  alongside its severity, and the score multiplies the two:

  | Confidence | Weight | Meaning |
  | --- | --- | --- |
  | `CONFIRMED` | ×1.25 | palar sent a payload and a callback came back. Settled. |
  | `OBSERVED` | ×0.6 | The defect is present in the definition palar read. |
  | `UNVERIFIED` | ×0.25 | Inferred from a field's name and shape. |

  Two rules sit on top of the arithmetic, stated rather than derived, and
  they mirror each other: **any `CONFIRMED` finding forces grade F**, and
  **`UNVERIFIED` findings alone can never reach F** (floor at D). The second
  is not redundant — per-rule dampening sums to `2*sqrt(n)` rather than
  converging, so without it ~65 unverified mediums would have landed back in
  F with nothing demonstrated about any of them. The numeric score is never
  rewritten to agree with a clamped letter, so it still ranks total
  exposure. Reports gained a "Findings by confidence" breakdown, and each
  finding's heading now carries both axes.

- **`scan --from-command` / `scan --from-url`.** Tool definitions can come
  from a running server over a real MCP connection instead of a
  hand-authored JSON file, and feed the identical rule set. Enumeration
  only: `listTools()` once, no tool call, no payload, no oracle.
  `--from-command` runs in the live sandbox under the same host lock, with
  no permitted network egress at all. `--from-env KEY=VALUE` sets variables
  inside that container; nothing is inherited from palar's own process.

- **`--container-start-timeout-ms`** (default 120000), separating palar's
  own container start from the target's responsiveness.

- **`scan <file.json>`** accepts a file path, as `--help` has always
  documented. It previously threw a raw `ENOTDIR` and exited `0`.

### Changed

- **Never-reached semantics.** A live run that never obtained a tool list is
  no longer reportable in a shape a clean pass could produce. A pre-flight
  (shared with `--from-command`) refuses a declared command naming no
  program on disk, before any Docker state exists — a manifest declaring
  `python -m mcp_server_fetch` is refused there rather than starting a
  container in which `python` reaches Node as a *script path*. The report
  prints no probe sections at all, since a page of "CONFIRMED: None." reads
  as a target that was exercised and came back clean.

- **Timeouts measure what they are named for.** Connect raised 30000 →
  90000 and now starts once the container is **running**; the overall scan
  ceiling raised 60000 → 180000; sandbox setup (Docker preflight, image
  builds, network, oracle) is outside the scan deadline entirely and
  announces image builds. Phase timings (`sandboxSetupMs`,
  `containerStartMs`, `connectDurationMs`) are reported separately, so a
  slow scan says whether the target was slow or palar was. Measured
  handshakes on Docker Desktop range from 1.3s (`playwright-mcp`) to 44–53s
  (`desktop-commander`, which waits out its own HTTP timeout fetching
  feature flags the sandbox denies it).

- **`--version` is read from `package.json` at runtime** rather than
  duplicated as a literal, and there is no fallback default. 0.2.0 shipped
  with the binary still reporting `0.1.0`; a version string that is wrong
  misreports rather than fails, which is why the reader throws instead of
  guessing. The same value is what targets see in the MCP handshake.

### Fixed

- **Probe filler no longer invalidates its own probes.** palar generates
  schema-satisfying values for fields it is not targeting, and probes whose
  arguments still violate the target's *declared* schema are reported as
  `NOT TESTED` rather than `REJECTED`. `desktop-commander` declares
  `origin: {"enum":["ui","llm"]}` on eight tools; palar's filler bounced at
  the top of the handler, and `start_process.command` — a field that really
  does reach a shell — came back reading "REJECTED BY TARGET". That is a
  false reassurance about the most dangerous tool in the sample, produced
  entirely by palar's own bad input.

- A `--timeout-ms` shorter than sandbox setup killed the process outright
  with an unhandled rejection (no report, no exit code) and leaked the
  sandbox network. The scan deadline is now armed after setup returns.

- `NB-001` no longer fires on absent declarations; `DH-001` is retuned to a
  size observation rather than implying hidden content.

## 0.2.0

- Docker sandboxing for `live` stdio targets, host-wide scan lock, OWASP MCP
  Top 10 compliance references, semantic snapshot diffing, and the initial
  live-probe pass.

  Published with the binary reporting `0.1.0` from a hardcoded literal; see
  the `--version` note under 0.3.0.
