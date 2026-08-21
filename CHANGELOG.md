# Changelog

All notable changes to `palar` are documented here.

This project is pre-1.0. Under `0.x`, minor releases may change behaviour;
the "Behaviour changes" section of each entry is the part to read before
upgrading a CI gate.

## Unreleased

### Behaviour changes

- **BREAKING (report/JSON output): `exposedHosts` findings are now addressed
  by value, not by array index.** `servers["s"].network.exposedHosts[0]`
  becomes `servers["s"].network.exposedHosts["10.0.0.5"]`. An index-based
  path is the one shape that can silently point at a *different* host after
  a harmless reorder, which would move an acknowledgement onto something
  nobody accepted. Nothing inside palar consumed the old shape — snapshots
  store tools only and never findings or paths, and the two structural
  jsonPath parsers (`live/escalate.ts`, `live/report.ts`) anchor on
  `tools[...]` — so no stored baseline breaks. Downstream tooling parsing
  `--json` for that literal path is the one thing that will notice.

- **`Finding` gained `supersedes`.** `live/escalate.ts` rewrites a static
  ruleId into the confirmed one (`IV-001` → `IV-101`) on the same field,
  and that provenance was previously recoverable only from prose inside
  `detail`. It is now structured, so anything matching findings across runs
  can follow the chain.

- **New `.palarrc.json` key: `acknowledgements`.** Findings a project has
  accepted, with a reason. Old configs are unaffected (`configVersion`
  stays `1`).

### Added

- **Acknowledgements** — see README's "Accepting a finding you already know
  about". Keyed on `(ruleId, jsonPath)` with supersession aliasing and
  optional `file` narrowing; `reason` and `added` required; `expires`
  optional but required and ~1-year-capped for `acceptsConfirmed`; 90-day
  staleness and 14-day pre-expiry warnings; unmatched entries surfaced
  always with fixed-vs-moved detection, fatal under
  `--strict-acknowledgements`, and quieted for live-only rule ids during a
  static scan.
- `--strict-acknowledgements` on `scan` and `live`.
- A loud **ACCEPTED** section in the Markdown report; `accepted` on findings
  in `--json`.

### What acceptance deliberately does NOT do

It does not remove a finding, discount it, change its severity or
confidence, or move the score or the grade. `confirmedForcesF()` is
untouched and unreachable from config: a callback-proven finding still
grades F no matter what `.palarrc.json` says. Acceptance changes only
whether `--fail-on` fails the build.

- **`palar live` may now send one extra call per errored tool: a benign
  *control call*.** Same tool, schema-valid benign arguments, no payload,
  used to tell "the target refused our payload" apart from "this tool could
  not run here at all". It is gated (see below), sent only for a probe that
  would otherwise read `rejected`, sent only after that probe, and made at
  most once per tool per scan. Bounded by the new `--control-timeout-ms`,
  which defaults to `--callback-timeout-ms`.

- **New probe status `inconclusive`, and it can change a CI exit code.** A
  probe whose error is matched by an errored control call is no longer
  reported as `rejected`. It resolves between `not-tested` and `rejected`,
  is excluded from coverage, and escalates no severity. A run in which no
  probe exercised its field now exits `2` — previously that required every
  probe to be `NOT TESTED`, and an all-`inconclusive` run would have exited
  `0`. There is deliberately **no majority threshold**: partial coverage is
  reported as a count, never as a pass/fail cliff.

- **`rejected` is now rendered in two tiers.** A rejection backed by a
  clean control call reads `(control call ran clean)`; one where the gate
  withheld the control reads `(NOT CONTROLLED)`. Anything parsing report
  headings should expect the suffix.

- **`runPoisoningCheck` no longer calls every poisoned tool.** That path
  has always sent a benign call with no side-effect gate at all — it
  predates the gate — and it is now gated by the same rule as the control
  call. A poisoned tool that the gate refuses reports the poisoning (which
  rests on the description, not on calling anything) and states that no
  direct call was made. Its behavioural sample is genuinely lost.

### The control-call gate

An annotation may only ever **subtract** permission, never grant it:

- `destructiveHint: true` vetoes. A danger claim is trusted because it
  costs the declarer something.
- A *safety* claim (`readOnlyHint: true`, `destructiveHint: false`) grants
  nothing, ever. It is exactly what a hostile server would write.
- Silence grants nothing either — the spec's default for an undeclared
  `destructiveHint` is `true`.

Permission comes from containment instead. **SSE targets are refused
outright** (no sandbox exists to bound the call), as is any tool whose name
matches palar's own destructive-verb list. Known incoherence, recorded in
`live/control.ts` rather than hidden: the *probe* path has no transport
branch, so an SSE target already receives injection payloads. That is a
separate decision and was not made here.

### Added

- `live/control.ts` — the control call, its gate, and shared benign
  argument construction.
- `live/coverage.ts` — "how many probes actually exercised their field",
  extracted so the exit-code rule is testable without running the CLI.
- A COVERAGE headline in the live report and a `coverage: N/M` line on the
  CLI, printed whenever probing happened.
- `--control-timeout-ms`.

### Notes

Measured, not estimated: the probing phase is ~99% oracle-callback wait
(`waitForCallback` resolves only on a callback or the full timeout, so 12
probes x 4s accounts for the 48-49s phase). A control call has no callback
wait, so its marginal cost is one bare round trip — median 6ms, max 70ms
over 15 calls against the `vuln-server` fixture in the real sandbox. The
timeout exists for tools that *block*, not for ones that are slow.

`inconclusive` establishes only that the payload was not the cause. It does
not say why, and the leading suspect is usually palar's own sandbox — no
egress, read-only mount, dropped capabilities, no DNS — rather than the
target. Every inconclusive entry in the report says so.

- **Scores can move on a server that declares annotations or a title, with
  no flag changing.** Two new finding sources exist: `TA-101` (live only,
  `high` · `CONFIRMED`) and the `TS-*` rules now scanning `title`. Because
  `TA-101` is `confirmed`, a run containing one grades `F` — the existing
  `confirmedForcesF()` rule, which `compliance.ts` already documented as
  applying to a confirmed finding that is not `critical`. Note this can only
  arise alongside an `IV-101`, which already forced `F` on its own.

- **A `.palar-snapshot.json` taken before this release compares cleanly, but
  a tool that declares a title or annotations now hashes differently.**
  Those fields joined the hashed material so an annotation-only flip is
  detectable at all. Both are folded in only when present, so a tool
  declaring neither hashes exactly as it did before and an old baseline does
  not read as wholesale drift.

### Added

- **`TA-101`: annotations contradicted by a probe.** MCP tool annotations
  are the tool's claims about what calling it does, and clients read them to
  decide whether to ask you first. Nothing enforces them. When a probe's
  out-of-band callback arrives, palar holds both halves of a contradiction —
  the claim, read from the server's own `listTools()`, and a demonstration
  of the opposite — and reports it as its own finding rather than as more of
  the injection. A confirmed command injection refutes `readOnlyHint: true`,
  `destructiveHint: false`, and `openWorldHint: false`; a confirmed SSRF
  refutes `openWorldHint: false` and nothing else, because a server-side GET
  may leave the server's own environment untouched. **A hint the server
  never declared is never contradicted** — the spec's defaults are not
  substituted for a declaration that was never made.

  `high` rather than `critical`: the exploitable primitive already carries
  `critical` under `IV-101` from the same callback, and stacking a second
  would weigh one piece of evidence twice. This is the separate defect of
  the declaration that removes the approval prompt.

- **`fixtures/contradiction-server`.** A second live fixture, whose tools
  declare `readOnlyHint: true` while reaching a shell and
  `openWorldHint: false` while fetching an attacker-supplied URL. Three of
  its declarations are deliberate controls that must NOT fire, including a
  genuinely exploitable tool that declares nothing at all.
  `fixtures/vuln-server` is untouched — the demo transcript on the site is
  generated from a real run of it.

- **`title` scanned as a third display surface.** The `TS-*` code-point
  rules now read `title` alongside `name` and `description`, in both spec
  positions (top-level `title` and `annotations.title` — two of the six
  sample targets use one, three use the other). Title is what a client's UI
  renders to the person doing the approving, and the spec warns it may not
  faithfully describe the tool. This widens where the existing checks look;
  it is not a new check, and on a benign server it produces no additional
  findings.

- **Annotation drift, on its own axis.** `ChangeClassification` gains a
  fourth value, `claim-relaxed`, for a tool that starts declaring itself
  safer than it did — `readOnlyHint` arriving at `true`, `destructiveHint`
  at `false`, `openWorldHint` at `false`, including from having declared
  nothing, since the spec's defaults are the dangerous side. It marks the
  tool `regressed` like a schema loosening does, but keeps its own name:
  a dropped `required` flag is a verified change to what the schema
  permits, while an annotation flip is a change to what the server says
  about itself with nothing verified. Its `reason` entries are phrased as
  claims — "the server now claims ..." — so the two stay distinguishable in
  a line that has lost the classification field. The reverse direction
  (a tool newly declaring itself destructive) stays `neutral`: it makes a
  client gate harder and has no rug-pull shape.

### Fixed

- **`scan --from-url` and `--from-command` no longer strip `title`,
  `annotations`, and `outputSchema`.** The live enumeration path kept three
  fields and silently dropped the rest, so a rule reading any of them saw
  them on a `scan` of the JSON file and never on a live scan of the very
  same server. A field present in one path and absent in the other is worse
  than one neither path has: it makes the two commands disagree about a
  single server with no way to tell which is right.

### Known gaps

- **`TS-006` does not scan `title`.** Title joined the code-point rules
  (`TS-001`…`TS-005`) as a third display surface, but the confusables rule
  — mixed Latin/Cyrillic or Latin/Greek inside one word, and NFKC
  compatibility forms — still reads `name` only. This is a real gap, not an
  oversight: a title written as `Rеad file` with a Cyrillic `е` spoofs the
  label a client's UI renders, and palar does not currently catch it.

  It was left out because `TS-006`'s detection is identifier-shaped, and a
  title is prose. It splits on non-alphanumerics and requires a Latin letter
  in the same word, which is a good fit for a tool name and a looser one for
  a human-readable label that may legitimately carry a compatibility form
  (`№`, a fullwidth character in a CJK title). Extending it means deciding
  what a false positive on a display string costs, which is a judgement
  worth making deliberately rather than inheriting from the name rule.

  Recorded here so the decision is a decision. If it is revisited, the test
  to beat is a title that mixes scripts inside one word without firing on a
  title that is merely multilingual.

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
