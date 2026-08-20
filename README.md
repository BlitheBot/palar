# palar

A defensive analyzer for local MCP (Model Context Protocol) tool and server
definition files, with two distinct modes:

- **`scan` / `snapshot` / `drift`** (the original engine) — **read-only
  static analysis**. These commands read local JSON files and report on
  their structure only. They make **no network calls**, generate **no
  payloads**, and never execute or import the content they scan. Findings
  are reported with severities, remediation guidance, and an overall 0–100
  score with a letter grade.
  - `scan --from-url` / `scan --from-command` change only *where the tool
    definitions come from* — a live server rather than a JSON file — and
    then apply the identical rules. They enumerate (`listTools()`, once) and
    never call a tool. `--from-url` still spawns nothing; `--from-command`
    starts the server and therefore always does so inside the same Docker
    sandbox `live` uses. See "Scanning a running server" below.
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
| `schema-integrity` | IV-001, IV-002 | Potentially sensitive string inputs (`command`, `path`, `url`, `sql`, …) whose schema does not narrow the values they accept (no `enum`, `const`, or non-trivial `pattern`); sensitive-named tools with no input schema at all. **IV-001 is `medium` and explicitly a hypothesis** — see "Static is a hypothesis, the oracle is evidence" below |
| `text-sanitization` | TS-001…TS-005 | Hidden Unicode in tool names/descriptions: zero-width characters, bidi override controls, tag characters, stray variation selectors, non-printable controls — reported by code point, never echoed |
| `network-boundaries` | NB-001…NB-004 | Egress filtering explicitly declared off, filters with no allowlist, and exposed hosts pointing at loopback or private/link-local address space (including the cloud metadata range). These evaluate declared values only — a manifest that declares no network posture produces no network findings |
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

#### Static is a hypothesis, the oracle is evidence

IV-001 decides "execution-adjacent" from the **field's name**, and that is
the ceiling on what it can know. Nothing in a name tells you whether the
value reaches `exec()`, `fs.readFile()`, or a validator that rejects it.
Measured across six real servers, 24 of 29 findings were IV-001 on fields
that turned out not to be injectable — every one of `server-filesystem`'s
eleven `path` fields fired, and a live probe showed palar's own payloads
arriving as literal filenames ("Parent directory does not exist:
/tmp/&lt;payload&gt;"). There was no shell to inject into, and the
containment lives in the handler, where a schema rule cannot see it. The
inverse error exists too: `browser_run_code_unsafe` calls itself
RCE-equivalent in its own description and gets no finding, because `code`
is not a keyword.

#### Confidence is scored separately from severity

Every finding carries a **confidence** alongside its severity, and the score
multiplies the two. They answer different questions — severity asks *how bad
is this if it is real*, confidence asks *how much of this did palar
establish* — and collapsing them is what made `server-filesystem` score
20/F on eleven findings whose own text calls them hypotheses.

| Confidence | Weight | What it means |
| --- | --- | --- |
| `CONFIRMED` | ×1.25 | palar sent a payload and an out-of-band callback carrying that probe's nonce came back. Settled. |
| `OBSERVED` | ×0.6 | The defect is present in the definition palar read — the bidi override, the credential, the declared loopback host really are there. Not a guess; also not a demonstrated runtime route. |
| `UNVERIFIED` | ×0.25 | Inferred from a field's name and shape. Every static `IV-*` rule. Worth looking at; not a demonstrated defect. |

Two rules sit on top of the arithmetic, stated rather than derived, and they
are deliberate mirrors of each other:

- **Any `CONFIRMED` finding forces grade F**, whatever the number says.
  palar watched it happen, and a settled result is not a matter of degree.
  Today the weights would reach F on their own for a confirmed *critical* —
  but that is a coincidence of three constants, and a future confirmed class
  at a lower severity would silently start passing a gate.
- **`UNVERIFIED` findings alone can never reach F**; the grade floors at D.
  A field-name heuristic must be able to move a grade but never decide one,
  and the per-rule dampening sums to `2*sqrt(n)` rather than converging — so
  without this floor ~65 unverified mediums would land back in F with
  nothing demonstrated about any of them. One `OBSERVED` finding lifts the
  floor: a fact in the file is allowed to carry a result to F on its own.

The numeric score is never rewritten to agree with a clamped letter. It
still ranks total exposure, so `desktop-commander` (11/F, one confirmation)
and `vuln-server` (0/F, two confirmations plus six observed findings) stay
distinguishable.

Measured across the sample, before and after this axis existed:

| Target | Tools | Findings | `scan` | `live` | Confidence mix |
| --- | --- | --- | --- | --- | --- |
| desktop-commander | 26 | 15 | 4/F → **72/C** | 0/F → **11/F** | 1 confirmed, 3 observed, 11 unverified |
| server-everything | 13 | 0 | 100/A → 100/A | 100/A → 100/A | — |
| mcp-server-fetch | 1 | 1 | 85/B → **96/A** | *never reached — no score* | 1 unverified |
| server-filesystem | 14 | 11 | 20/F → **80/B** | 20/F → **80/B** | 11 unverified |
| server-memory | 9 | 1 | 85/B → **96/A** | 85/B → **96/A** | 1 unverified |
| playwright-mcp | 24 | 2 | 74/C → **94/A** | 74/C → **94/A** | 2 unverified |
| `vuln-server` fixture | 3 | 8 | 0/F → **0/F** | 0/F → **0/F** | 2 confirmed, 6 observed |

Score normalization by tool count is deliberately **not** applied, and this
is why it is not needed: playwright-mcp (24 tools, 2 findings) used to score
11 points worse than mcp-server-fetch (1 tool, 1 finding); it now scores 2
points worse, and those 2 points are exactly "two findings instead of one".
The punishment was never really about tool count — it was 24 tools' worth of
accumulated hypotheses. Dividing the penalty by tool count would also let a
server dilute a confirmed injection by shipping more clean tools.

So the two tiers say different things, and palar keeps them apart:

- **Static (`scan`) states a hypothesis at `medium`,** in wording that says
  so. Its remediation does not claim a schema constraint is definitely the
  fix, because for a server that enforces containment in code it would
  break the server without making it safer.
- **A CONFIRMED oracle callback (`palar live`) settles it and escalates the
  same finding to `critical`,** rewriting it to carry the evidence — the
  probe's nonce, the time, the address it came back from, and the payload
  sent. The score is recomputed, so `--json` and `--fail-on` see it too.
- **A `rejected` probe changes nothing.** The target answered with an
  error, and that one boolean spans a handler refusal, a bounce on a rule
  the schema never declared, and an injected command that ran and exited
  nonzero.
- **A `not-tested` probe changes nothing either, for the opposite reason.**
  The call failed while palar's own arguments already violated the schema
  the target published, so the field was never exercised. It is reported as
  missing coverage, not as a result.

**The tradeoff this makes, stated plainly:** a genuinely injectable field
now reads `medium` until something proves otherwise. `start_process.command`
on desktop-commander really does reach a shell, and a static-only scan now
scores it exactly the same as `read_file.path` on server-filesystem, which
does not. Static analysis cannot tell those apart — that is the whole
point — but the flattening is real, and `palar live` is what recovers the
distinction.

**palar never reports a score for something it did not examine.** When a
scan finds no definitions, or cannot reach a live source, or reaches one
that exposes no tools, the report and the `--json` document carry an
`outcome` and **no `score` field at all** — an absent score cannot be
misread, whereas a perfect grade for zero inputs is read exactly wrong, and
it is read that way by the CI job treating it as a passing gate.

### Scanning a running server: `--from-url` / `--from-command`

By default `scan` analyses tool definitions as somebody wrote them down in
a JSON file. These two flags take the definitions from the server itself
instead — one real MCP connection, one `listTools()` call — and run the
identical rule set over the result. Same rules, same score, different
source of truth. That matters because the two genuinely disagree: palar's
own `fixtures/vuln-server/mcp.tools.json` declares an `apiKey` property with
a hardcoded default that the running server does not declare at all.

**Enumeration only.** Neither flag ever calls a tool, builds a payload, or
starts the callback oracle. That is what makes `--from-url` safe to point
at a server you do not own, and it is why the `--from-command` sandbox runs
with no permitted network egress whatsoever. To actually exercise a tool,
use `palar live`, which is a different command with its own consent gate.

```sh
# A server running somewhere else, over SSE. Spawns nothing, no Docker, no lock.
palar scan --from-url http://127.0.0.1:3000/sse

# A Node server already installed on this disk. Always sandboxed, always locked.
palar scan --from-command node node_modules/@scope/server/dist/index.js

# A server you are developing, with its own flags after `--`
palar scan --from-command node ./dist/index.js -- --headless --isolated
```

- `--from-url <url>` — connect to an already-running server. It spawns no
  process, creates no container, and takes no lock; its entire footprint is
  one outbound connection. **SSE endpoints only** — that is the transport
  the connector implements, and a streamable-HTTP URL will simply fail to
  connect.
- `--from-command <command...>` — start the server and read its tool list.
  It **always** runs inside the same Docker container sandbox `palar live`
  uses and **always** takes the host-wide live-scan lock. There is no flag
  to opt out of either and no prompt offering to, by design. A token
  starting with `-` ends the variadic list, so pass the target's own flags
  after a bare `--`.
- `--from-env KEY=VALUE` (`--from-command` only, repeatable) — set an
  environment variable inside the container. Nothing is inherited from
  palar's own process, so a server that stores state under `$HOME` needs
  `--from-env HOME=/tmp` (the container's root filesystem is read-only and
  only `/tmp` is writable).
- `--connect-timeout-ms` (default 90000) / `--timeout-ms` (default 180000) —
  the connect/handshake budget and the hard ceiling for the whole
  enumeration. A `--from-command` target has to start a container before it
  can answer, and some servers do work at startup before responding to
  `initialize`; measured against desktop-commander that is 44–53 seconds on
  Docker Desktop. See `live`'s per-target table below for the full range.

#### What `--from-command` can and cannot run

The sandbox provides a **Node runtime**, a **read-only bind mount** of the
server's own directory, and **no network or DNS at all**. Everything below
follows from that, and it is stated here rather than discovered later:

- **Works:** a Node server that is already present on this disk. A server
  you are developing (`--from-command node ./dist/index.js`), or an
  installed package (`--from-command node node_modules/@scope/server/dist/index.js`).
  The mount root is derived from the program path — for a package under
  `node_modules`, palar mounts the directory *containing* the outermost
  `node_modules`, because the package's own dependencies are siblings
  there, not children.
- **Does not work:** anything that must be fetched in order to run —
  `npx -y @scope/server`, `uvx`, `pipx` — because there is no network to
  fetch it with; and anything needing a runtime other than Node — Python,
  Go, a compiled binary — because the image does not have one. Install the
  server first and point `--from-command` at the installed entry point.

A registry-fetch invocation is refused at plan time, before any lock is
taken or container started, rather than being allowed to fail later as a
connect timeout that reads like a broken target. A target that starts and
then dies has its own stderr attached to the failure, so "never reached"
comes with the evidence.

#### Exit codes

| Outcome | Exit | Score emitted? |
| --- | --- | --- |
| Definitions examined | `0` (or `1` with `--fail-on`) | yes |
| No definition files discovered | `0` (or `1` with `--fail-on-empty`) | no |
| Connected, server exposes zero tools | `1` | no |
| Never reached (no connection, or an unsupported invocation) | `2` | no |

The last two are deliberately distinct. "Reached it, there is nothing to
examine" is a statement about the target; "never reached it" is a statement
about nothing at all.

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
description hygiene) are reported **STATIC-ONLY**. These categories are
always kept visibly separate in the report — never flattened into one list.

**A probe only carries the payload on one field**, and everything else in
the call is filler palar generates from the target's declared schema. That
filler honors `enum`, `const`, `format`, length and numeric bounds,
`minItems`, and nested `required` objects, and palar sends only the
properties the schema marks required — an invented value for an optional
knob changes what the tool does. (desktop-commander declares an optional
`origin: {"enum":["ui","llm"]}` on eight tools and an optional
`shell: {"type":"string"}` on `start_process`; filling the first bounced
every probe at validation, and filling the second would have run the
payload through a shell that does not exist.)

Where the schema declares something filler cannot satisfy — an arbitrary
`pattern`, a contradictory bound — palar knows that *before it sends*, and
a call that then fails is reported **NOT TESTED** rather than
ATTEMPTED — REJECTED: the failure is explained by palar's own input, so
nothing was learned about the probed field, and its static finding stays
listed under STATIC-ONLY. That check is exact for constraints the target
declared and blind to ones it only *enforces*; a probe bounced by an
undeclared rule still reads REJECTED, because telling those apart would
mean guessing from free-form error text.

```sh
palar live fixtures/vuln-server --execute
```

`--execute` is required — `live` refuses to run without it, since (unlike
`scan`) it has real side effects. Other flags: `--timeout-ms` (hard ceiling
for the scan per server, default 180000), `--connect-timeout-ms` (how long
to wait for the target to answer the handshake, default 90000),
`--container-start-timeout-ms` (palar's own container start, default
120000), `--callback-timeout-ms`, `--oracle-host` (default `127.0.0.1`, SSE
targets only — see below), `--json`, `--out`.

#### What each timeout actually measures

A live scan has three phases, and only one of them is about the server.
They are budgeted and reported separately, because charging palar's own
setup to a timeout named for the target produced a "never reached" verdict
about a server that had not been asked anything yet.

| Phase | Bounded by | Whose latency |
| --- | --- | --- |
| Docker preflight, building the sandbox images, network, oracle, firewall | *nothing* — see below | palar's |
| `docker run` reaching a running container | `--container-start-timeout-ms` (120000) | this machine's Docker daemon |
| The target answering the MCP handshake | `--connect-timeout-ms` (90000) | **the server's** |
| Everything after that (listTools + every probe) | `--timeout-ms` (180000) | the server's |

**Setup is not raced against `--timeout-ms` at all.** On a first run it has
to fetch a ~300MB base image and install into it — palar building its own
tools, not a target being slow. It announces itself instead (`building the
sandbox image … first run only`), and a failure there says it was palar's
setup that failed rather than blaming the server.

The deadline is armed *after* setup returns, and that ordering is load-
bearing rather than cosmetic: nothing awaits the deadline until the scan's
own race, so a timer armed before setup rejects with no handler attached.
That is an unhandled rejection, which kills the process outright — no
report, no exit code, and the sandbox network already created is leaked for
the next run's sweep to reclaim. There is a regression test
(`setup-deadline.test.ts`) that runs a scan with a 1ms budget and asserts
setup still completes.

`--connect-timeout-ms` starts counting **once the container is running**, so
it measures target responsiveness alone. Measured on Docker Desktop with
warm images, palar's own overhead is ~2.5s of setup plus ~0.6s of container
start; the target handshake by comparison:

| Target | Handshake |
| --- | --- |
| `playwright-mcp` | 1.3–3.2s |
| `server-memory` | 4.5–7.0s |
| `server-everything` | 5.4–8.0s |
| `server-filesystem` | 5.2–10.1s |
| `vuln-server` fixture | 7.2–15.9s |
| `desktop-commander` | 44.0–53.4s |

`desktop-commander` is why the default is 90000 and not less: it fetches
remote feature flags before answering `initialize`, and the sandbox denies
it that network, so it waits out its own HTTP timeout first. At the previous
30000 default the most dangerous server in the sample reported as a connect
failure and produced nothing, every run. `--timeout-ms` bounds the scan and
races the handshake, so keep it the larger of the two or it preempts this
one.

#### Exit codes

| Outcome | Exit |
| --- | --- |
| Something was CONFIRMED by an oracle callback | `1` |
| palar examined nothing — no target reached, every target reached had zero tools, or every probe was NOT TESTED | `2` |
| At least one target was reached and probing happened (including partial coverage) | `0` |

`2` is the same code, for the same reason, that `scan` uses for a target it
never reached: a scan that exercised nothing must not exit `0` alongside a
scan that exercised everything and found it clean. A confirmed finding
outranks it — a result beats a report about coverage. Partial coverage
exits `0` with a warning naming how many probes did not land; whatever did
run really ran.

Note `live`'s `1` and `scan`'s `1` mean different things (`scan` uses it
for "reached, zero tools"). That is why `live` folds its own zero-tools
case into `2` rather than matching `scan`'s numbering: `live`'s `1` is the
CONFIRMED gate, and a coverage gap must never be reported as a
confirmation.

#### A target that was never reached

`live` refuses to describe a target it never spoke to in a shape a clean
pass could also produce. Before starting anything, it checks that the
server's declared `command`/`args` name a program that exists under the
mount — the same pre-flight `scan --from-command` has always run. A
manifest declaring `python -m mcp_server_fetch` is refused there, with the
reason, rather than starting a container in which `python` reaches Node as
a *script path* and dies as `Cannot find module '/target/python'`.

When no target is reached — by that check, by a connect timeout, by a
container that never started — then:

- the exit code is `2`, never `0`;
- the report says `NEVER REACHED` and prints no probe sections at all (a
  page of "CONFIRMED: None." reads as a target that was exercised and came
  back clean, which is the opposite of what happened);
- `--json` carries `"outcome": "never-reached"` and **no `score` field**.
  The findings stay — they are observations about files palar really did
  read — but a grade is a summary verdict, and a run that spoke to no
  running server has no verdict. A CI job reads a grade as the answer to
  "did this pass?", and `85/B` for a target that never started is that
  question answered wrong.

On a mixed run, `--json` carries `"outcome": "partial"`, every unreached
server is named on its own red status line, and the exit code is decided by
the servers that did answer.

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
- **live scans are serialized on the host by an exclusive lock.** `live`
  takes a single lock file before it touches any sandbox state and holds it
  for the whole run, so a second invocation on the same machine refuses to
  start (`another palar live scan is running (pid N, started ...)`) rather
  than racing the first on the shared netfilter chains below. The lock
  lives in a per-user app state directory — `$XDG_STATE_HOME/palar`
  (falling back to `~/.local/state/palar`) on Linux/macOS,
  `%LOCALAPPDATA%\palar` on Windows — deliberately **not** the OS temp
  directory, where a tmp cleaner deleting a live scan's lock mid-run would
  silently reopen the race;
- a lock left behind by a crashed run does not wedge the tool. Staleness is
  decided by process identity, never by age: the recorded pid is checked
  for existence, and its recorded start time is compared against the live
  process's actual start time so a recycled pid can't masquerade as the
  original holder. A dead or recycled holder's lock is broken, reclaimed
  and reported; a genuinely live one is refused. There is no timeout
  heuristic, because a legitimately long scan must never become
  reclaimable while it is still firewalling a running container;
- on startup, `live` sweeps up sandbox state orphaned by an earlier run
  that never reached teardown (a crash, a kill, a Ctrl-C): leftover
  `mcpg-*` containers and networks and `MCPG-*` chains with their
  `DOCKER-USER`/`INPUT` jumps. It reports what it reclaimed rather than
  cleaning up silently. This matters because a `docker run` client killed
  by Ctrl-C does *not* stop the container it started, so an orphan can
  otherwise outlive the scan indefinitely. The sweep reclaims *every*
  `mcpg-`/`MCPG-` object without trying to tell whose it is, which is safe
  precisely because the lock above guarantees no other live scan exists to
  own one.

The oracle binds to whichever address is actually reachable on the detected
Docker backend (host loopback on Docker Desktop; that scan's bridge network
gateway on native Linux Engine, where a loopback-bound listener isn't
reachable from inside a container), so `--oracle-host` only affects the SSE
case.

**What this is, plainly stated:** Docker + `iptables` container isolation,
not a VM and not gVisor — a kernel-level container escape is not mitigated.
Named gaps, not silently deferred:

- the `DOCKER-USER` and `INPUT` chains are shared, host-global state.
  Concurrent `palar live` runs are no longer a race — they are prevented:
  the host lock described above serializes them, so a second invocation
  refuses instead of interleaving jump-rule inserts/deletes or sweeping the
  first scan's live firewall away. **The lock is host-local, and that is
  the remaining gap:** two *separate machines* pointed at the same remote
  Docker daemon (via `DOCKER_HOST` or a shared socket/TCP endpoint) are
  still unprotected. Neither can see the other's state directory, and pids
  aren't comparable across hosts, so the original race — and the startup
  sweep reclaiming the other machine's live container and chains — applies
  in full. Don't point two machines' `palar live` at one shared daemon. A
  lock file written on another host is detected by hostname and refused
  rather than guessed at, but that only covers a *shared state directory*
  (a roamed or network-mounted home), not a shared daemon;
- **both Docker backends have been measured end-to-end, but not with the
  same freshness or the same coverage.** Native Linux Docker Engine is
  verified continuously by
  [`.github/workflows/canary.yml`](.github/workflows/canary.yml), which runs
  daily on a GitHub-hosted `ubuntu-latest` runner — a full VM on native
  Engine, so the Linux branch is what executes there. It asserts a *pair* of
  results that only hold together if the firewall genuinely discriminates:
  the oracle callback lands (the sandbox reached the host on the one
  ACCEPTed port) while a host listener verified up on a separate sentinel
  port is unreachable from that same container. It also asserts DNS does not
  resolve inside the sandbox, and that no container, network, `MCPG-*` chain
  or lock file survives teardown. Docker Desktop (Windows/WSL2) was measured
  by hand — same paired controls, by dumping live netfilter state mid-scan
  and probing from inside the running sandbox — but **as of 2026-08-20,
  with nothing re-checking it since**; that date is the age of the
  evidence, and it only gets older. That measurement recorded: the scan’s
  `MCPG-<id>` chain carrying exactly one `ACCEPT` (the oracle’s host:port
  for that scan) followed by a catch-all
  `REJECT --reject-with icmp-port-unreachable`, reached from both the
  `DOCKER-USER` (forwarded) and `INPUT` (host-destined) hooks; 2 of 2
  probes CONFIRMED by oracle callback; a host sentinel listener, verified
  up before and after the run, refused from inside the sandbox with
  `ECONNREFUSED` in 7ms — a REJECT signature, not a DROP timeout; and
  `dns.lookup()` failing `EAI_AGAIN` in 23ms, the fast shape
  `BLACKHOLE_DNS` predicts rather than the slow one that would indicate a
  resolver genuinely reaching out. That check is
  [`scripts/desktop-canary.sh`](scripts/desktop-canary.sh) — run it to
  reproduce those values, and update this date and the one in
  `src/live/sandbox.ts` when you do. It refuses to run on any backend other
  than Docker Desktop, so a green result can never be filed against the
  wrong one. What the canary does *not* cover: it exercises one host
  netfilter configuration (Ubuntu 24.04, where `iptables` is the nft-backed
  shim and dockerd follows it). Hosts that resolve `iptables` to the legacy
  backend, or that have no iptables compatibility layer at all — where these
  rules may not apply as written — remain untested; re-run those checks
  before trusting the sandbox there;
- **Docker Desktop's verification is structurally manual and will age.**
  This is a standing limitation, not a task someone has yet to get to: no
  hosted CI runner offers Docker Desktop as a backend. GitHub's runners are
  native-Engine VMs — which is precisely why the canary exercises the Linux
  path — and Docker Desktop's licensing and nested-virtualization
  requirements rule out installing it on one. So the containment claims for
  the backend that leans hardest on Docker-Desktop-specific machinery
  (`host.docker.internal`, the internal host-proxy IP resolved per scan)
  rest on a hand-run measurement that nothing can automatically refresh.
  Assume that evidence is as old as the date above, and re-measure by hand
  if you need it current;
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

A path may be a **file** as well as a directory — `palar scan
./config/mcp.tools.json` reads exactly that file. The naming conventions
above still decide which analyser it gets, because the two rule sets are
different and nothing in a bare JSON object reliably says which one it is;
running the wrong one produces confident findings about the wrong thing. So
a named file whose name matches neither convention is refused with a
message saying so and naming the patterns, and a path that does not exist
is reported as such rather than being silently indistinguishable from an
empty directory.

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
  live/       Everything that talks to a running server. Shared by both
              `live` and `scan --from-url`/`--from-command`: connector
              (real stdio/SSE MCP client via @modelcontextprotocol/sdk),
              sandbox (per-scan Docker container + network + iptables
              egress control for stdio targets, with the allow-port
              explicit so an enumeration installs no ACCEPT hole), lock
              (host-wide serialization). Used by `live` alone: oracle
              (local HTTP callback listener), probes (payload
              classification and construction, reusing
              rules/input-validation.ts's keyword matching), liveScan
              (orchestrator), status (probe status resolution), report
              (CONFIRMED / NOT-TESTED / ATTEMPTED-REJECTED /
              ATTEMPTED-UNCONFIRMED / STATIC-ONLY rendering), escalate
              (a confirmed callback rewriting the static finding). Used by
              `scan --from-*` alone:
              enumerate (container command planning, listTools(), and the
              enumerated / no-tools / never-reached result union)
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
