# ⚠️ INTENTIONALLY VULNERABLE — FOR PALAR TESTING ONLY, DO NOT DEPLOY

A minimal, deliberately-broken MCP server used as a test fixture for
[Palar](../../README.md). It exists for one rule: **TA-101**, the
contradiction between what a tool's MCP annotations *claim* and what a live
probe *proves* it does.

Do not run it against anything other than your own local machine, and never
deploy it or expose it to untrusted callers.

## Why this is a separate fixture from `../vuln-server`

`fixtures/vuln-server` declares no annotations, and the demo transcript
published on the site is generated from a real run of it. Adding claims to
those tools to exercise TA-101 would change that transcript's input without
changing the page, so the page would go quietly stale. This fixture is
therefore new and self-contained, and `vuln-server` is left exactly as it
was.

## The tools, and which ones are controls

TA-101 fires only when Palar holds **both halves** of a contradiction: a
declaration read from the server's own `listTools()` response, and a
callback bearing a probe nonce that disproves it. Three of the six
declarations below are deliberately arranged so they must **not** fire —
a fixture where everything lights up cannot detect a rule that has become
too eager.

| Tool | Declares | Probe | Expected TA-101 |
| --- | --- | --- | --- |
| `probe_host` | `readOnlyHint: true` | command-injection via `hostname` | **contradicted** — running an arbitrary command is not read-only |
| `probe_host` | `openWorldHint: false` | command-injection via `hostname` | **contradicted** — the callback is an outbound request to an address that arrived in the payload |
| `probe_host` | `idempotentHint: true` | command-injection via `hostname` | *control:* declared, but not in the command-injection row of Palar's table — must not appear |
| `probe_host` | `destructiveHint` *(not declared)* | command-injection via `hostname` | *control:* no claim was made, so there is nothing to contradict |
| `load_reference` | `openWorldHint: false` | SSRF via `url` | **contradicted** — the server fetched an attacker-supplied URL |
| `load_reference` | `readOnlyHint: true` | SSRF via `url` | *control:* a server-side GET may leave the server's own environment untouched, so the `ssrf` row claims only `openWorldHint`. If this ever fires, TA-101 has started inferring |
| `run_task` | *(no annotations at all)* | command-injection via `command` | *control:* confirms, and produces **no** TA-101 — proving the rule is silent because no claim was made, not because no callback arrived |

## The other two flaws, and why they are here

- **Both title positions.** `probe_host` carries a top-level `title`;
  `load_reference` carries `annotations.title`. Both are live in the wild,
  and a reader that knows only one position misses real titles — so the
  fixture covers both.
- **A poisoned title.** `load_reference`'s `annotations.title` hides a
  zero-width space (U+200B) followed by an instruction aimed at the calling
  model. This is the tool-poisoning shape moved onto the display surface a
  client's UI actually renders, and it is what the TS-\* rules could not see
  until they scanned `title` as a third surface alongside `name` and
  `description`. `palar scan` on this directory reports it as `TS-001` on
  `tools["load_reference"].annotations.title`.

Every "vulnerability" here is on purpose: `probe_host` and `run_task`
interpolate their argument directly into a shell command, and
`load_reference` fetches its `url` with no scheme, host, or IP-range
allowlist.

## Running it

Palar's `live` pass mounts this directory — and nothing above it — read-only
into the target's container, so the fixture needs its own `node_modules`:

```bash
cd fixtures/contradiction-server
npm install
```

No flags, no build step, any host. This fixture is **deliberately plain
JavaScript** so that a plain `npm install` on Windows or macOS produces a
`node_modules` the linux-x64 container can actually start from.

It used to be TypeScript, which required `tsx`, which pulls in `esbuild`,
whose binary is platform-specific: a plain install on a non-Linux host wrote
`@esbuild/win32-x64` (or `darwin-*`) here and the target died before the MCP
handshake, surfacing as `Connection closed` with an esbuild platform error in
the captured stderr. The workaround was `--os=linux --cpu=x64
--ignore-scripts`; the fix is to have no native dependency at all.

`@modelcontextprotocol/sdk` and `zod` are pure JS, no package in the tree
declares an `os`/`cpu` constraint or an install script, and there is no
build step. Please do not port this fixture back to TypeScript. Verify with:

```bash
npm ls --all          # no @esbuild, no tsx
```

Then, from the repo root:

```bash
npm run dev -- scan fixtures/contradiction-server   # static: annotations, titles, schemas
npm run dev -- live --execute fixtures/contradiction-server   # live: probes, and TA-101
```

The static scan reads `mcp.tools.json` / `mcp.server.json`; the live pass
runs `src/index.js` for real inside Docker via the `command`/`args` declared
in `mcp.server.json`. The two are kept in sync so both modes have a genuine
target rather than a schema on paper.
