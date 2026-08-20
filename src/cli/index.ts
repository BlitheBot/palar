#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { Command, InvalidArgumentError, Option } from "commander";
import chalk from "chalk";
import type { AuditResult, ScanJsonDocument, Severity } from "../core/types.js";
import type { ResolvedConfig } from "../core/config.js";
import { DEFAULT_LIMITS, loadConfigFile } from "../core/config.js";
import { discover } from "../discovery/index.js";
import { runAudit } from "../core/auditor.js";
import { VERSION } from "../core/version.js";
import {
  renderMarkdownReport,
  SEVERITY_ORDER,
  severityRank,
} from "../core/compliance.js";
import {
  buildSnapshot,
  diffSnapshotsDetailed,
  loadSnapshot,
  saveSnapshot,
} from "../core/snapshot.js";
import { runLiveScan } from "../live/liveScan.js";
import { escalateConfirmedFindings } from "../live/escalate.js";
import {
  describeSource,
  enumerateFromCommand,
  enumerateFromUrl,
  EnumerationPlanError,
  planContainerCommand,
  type EnumerationResult,
} from "../live/enumerate.js";
import { sweepOrphanedSandboxState } from "../live/sandbox.js";
import { ScanLock, ScanLockHeldError } from "../live/lock.js";
import { renderLiveMarkdownReport } from "../live/report.js";

const program = new Command();

function positiveInt(value: string): number {
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) {
    throw new InvalidArgumentError("must be a positive integer");
  }
  return n;
}

interface LimitOpts {
  config?: string;
  maxFileSize?: number;
  maxNestingDepth?: number;
  maxSchemaNodes?: number;
}

/**
 * Load config from --config / .palarrc.json (defaults when absent),
 * then layer CLI limit flags on top — flags always win over the file.
 */
async function loadCliConfig(opts: LimitOpts): Promise<ResolvedConfig> {
  const base = await loadConfigFile(opts.config, process.cwd());
  return {
    ...base,
    limits: {
      maxFileSize: opts.maxFileSize ?? base.limits.maxFileSize,
      maxNestingDepth: opts.maxNestingDepth ?? base.limits.maxNestingDepth,
      maxSchemaNodes: opts.maxSchemaNodes ?? base.limits.maxSchemaNodes,
    },
  };
}

const LIMIT_OPTIONS: [flag: string, description: string][] = [
  [
    "--max-file-size <bytes>",
    `max definition file size in bytes (default ${DEFAULT_LIMITS.maxFileSize})`,
  ],
  [
    "--max-nesting-depth <n>",
    `max schema nesting depth walked (default ${DEFAULT_LIMITS.maxNestingDepth})`,
  ],
  [
    "--max-schema-nodes <n>",
    `max schema nodes visited per tool per rule (default ${DEFAULT_LIMITS.maxSchemaNodes})`,
  ],
];

function addLimitOptions(cmd: Command): Command {
  cmd.option(
    "--config <path>",
    "path to a config file (default: ./.palarrc.json when present)"
  );
  for (const [flag, description] of LIMIT_OPTIONS) {
    cmd.option(flag, description, positiveInt);
  }
  return cmd;
}

program
  .name("palar")
  .description(
    "Read-only static analyzer for local MCP tool and server definition files"
  )
  .version(VERSION);

interface ScanOpts extends LimitOpts {
  dir?: string[];
  json?: boolean;
  out?: string;
  failOn?: Severity;
  failOnEmpty?: boolean;
  fromUrl?: string;
  fromCommand?: string[];
  fromEnv?: string[];
  connectTimeoutMs: number;
  timeoutMs: number;
}

/**
 * Parses `--from-env KEY=VALUE` assignments.
 *
 * A manifest-driven scan gets the target's environment from the manifest's
 * own `"env"` field; `--from-command` has no manifest, and some perfectly
 * ordinary Node servers do not start without one variable set (a server
 * that writes state under `$HOME` will not start at all against the
 * sandbox's read-only root filesystem). Without this flag those servers are
 * not scannable by `--from-command` at all.
 *
 * Named values only, never inherited: exactly these variables reach the
 * container, exactly as written on the command line. env.ts's contract — no
 * ambient host environment reaches a target just because it was in scope in
 * palar's own process — is unchanged, and deliberately so; a
 * `--from-env-passthrough` would hand a target whatever CI secrets happened
 * to be exported.
 */
function parseEnvAssignments(assignments?: string[]): Record<string, string> | undefined {
  if (!assignments || assignments.length === 0) return undefined;
  const env: Record<string, string> = {};
  for (const assignment of assignments) {
    const eq = assignment.indexOf("=");
    // Rejected rather than treated as `KEY=""`: `--from-env HOME` most
    // likely means "pass my HOME through", which is exactly what this
    // must not silently do.
    if (eq <= 0) {
      throw new InvalidArgumentError(
        `--from-env expects KEY=VALUE, got "${assignment}". Values are never inherited from ` +
          "this process's environment — write the value you want the target to see."
      );
    }
    env[assignment.slice(0, eq)] = assignment.slice(eq + 1);
  }
  return env;
}

/**
 * Splits the operands commander collected into real scan paths and the
 * tokens that followed a bare `--`.
 *
 * `--from-command <command...>` is variadic, and a variadic option stops at
 * the first token starting with `-`. That is fine for
 * `node ./dist/index.js` and useless for a target that takes its own flags
 * (`cli.js --headless --isolated`), which commander would reject as an
 * unknown option to palar. So everything after `--` is appended to the
 * command verbatim, the ordinary shell convention:
 *
 *   palar scan --from-command node ./cli.js -- --headless --isolated
 *
 * Commander funnels post-`--` tokens into the command's positional
 * operands, i.e. into `[paths...]`, where they are indistinguishable from
 * directories to scan. process.argv still knows the difference, so the
 * split is recovered from there rather than guessed at.
 */
function splitPassthroughOperands(
  operands: string[],
  hasFromCommand: boolean
): { paths: string[]; passthrough: string[] } {
  // Only --from-command reinterprets post-`--` tokens. Without it, `--` keeps
  // its ordinary meaning of "stop parsing options", and `palar scan -- ./dir`
  // must still scan ./dir rather than quietly dropping it.
  if (!hasFromCommand) return { paths: operands, passthrough: [] };
  const separator = process.argv.indexOf("--");
  if (separator < 0) return { paths: operands, passthrough: [] };
  const passthrough = process.argv.slice(separator + 1);
  // Post-`--` tokens are appended last, so trimming that many from the end
  // leaves exactly the operands the user wrote as paths.
  const keep = Math.max(0, operands.length - passthrough.length);
  return { paths: operands.slice(0, keep), passthrough };
}

/**
 * Writes whatever the scan produced, honoring --out and --json the same
 * way in every outcome — including the ones that produce no report. A CI
 * job that collects `--out report.md` should find a file saying the target
 * was never reached, not an absent file it has to infer a meaning for.
 */
async function emitScanOutput(
  body: string,
  opts: ScanOpts,
  logStatus: (message: string) => void
): Promise<void> {
  if (opts.out) {
    await writeFile(opts.out, body, "utf8");
    logStatus(chalk.dim(`report written to ${opts.out}`));
  } else {
    console.log(body);
  }
}

/**
 * Reports the outcome of a scan whose definitions came from a live server
 * rather than from disk, and sets the exit code.
 *
 * Exit codes are the contract here, and they are deliberately distinct:
 *   2 — never reached. Nothing is known about the target.
 *   1 — reached, zero tools. Something is known, and it is "nothing to
 *       examine", which is not the same as "examined and clean".
 * Neither emits a score. See ScanJsonDocument's docstring for why.
 */
async function reportUnexaminable(
  result: Extract<EnumerationResult, { outcome: "no-tools" | "never-reached" }>,
  opts: ScanOpts,
  logStatus: (message: string) => void
): Promise<void> {
  const source = describeSource(result.source);
  const timestamp = new Date().toISOString();

  if (result.outcome === "never-reached") {
    process.exitCode = 2;
    const doc: ScanJsonDocument = { outcome: "never-reached", timestamp, source, error: result.error };
    await emitScanOutput(
      opts.json
        ? JSON.stringify(doc, null, 2)
        : `# palar audit report\n\n- **Timestamp:** ${timestamp}\n- **Source:** ${source}\n` +
            `- **Outcome:** never reached — no score\n\n${result.error}\n`,
      opts,
      logStatus
    );
    logStatus(
      chalk.red(
        `Failing: never reached ${source} — ${result.error}. No score is reported: palar ` +
          "examined nothing, which is not the same as finding nothing."
      )
    );
    return;
  }

  process.exitCode = 1;
  const doc: ScanJsonDocument = { outcome: "no-tools", timestamp, source };
  await emitScanOutput(
    opts.json
      ? JSON.stringify(doc, null, 2)
      : `# palar audit report\n\n- **Timestamp:** ${timestamp}\n- **Source:** ${source}\n` +
          `- **Outcome:** connected, zero tools — no score\n\n` +
          "The server completed the MCP handshake and reported no tools, so there were no " +
          "definitions to analyse.\n",
    opts,
    logStatus
  );
  logStatus(
    chalk.red(
      `Failing: connected to ${source} but it exposes zero tools. No score is reported: there ` +
        "was nothing to examine."
    )
  );
}

/**
 * `scan --from-url` / `scan --from-command`: take the tool definitions from
 * a running server instead of from JSON files, then run the identical rule
 * set over them.
 *
 * The two flags have deliberately different host footprints, and the
 * difference is not configurable:
 *   - `--from-url` connects to a server somebody else is already running.
 *     No process is spawned, no container is created, no lock is taken.
 *   - `--from-command` starts a process, so it always runs in the Docker
 *     sandbox and always takes the host-wide live-scan lock. There is no
 *     flag to opt out of either, and no prompt offering to. A flag that
 *     lets a user run an untrusted server unsandboxed on their own host is
 *     a flag whose safe default exists only until someone is in a hurry.
 */
async function scanFromLiveSource(
  opts: ScanOpts,
  config: ResolvedConfig,
  passthrough: string[]
): Promise<void> {
  const logStatus = opts.json ? console.error : console.log;
  const enumerateOpts = {
    connectTimeoutMs: opts.connectTimeoutMs,
    overallTimeoutMs: opts.timeoutMs,
    env: parseEnvAssignments(opts.fromEnv),
  };

  let result: EnumerationResult;

  if (opts.fromUrl) {
    logStatus(chalk.dim(`connecting to ${opts.fromUrl} (SSE) to enumerate tools...`));
    result = await enumerateFromUrl(opts.fromUrl, enumerateOpts);
  } else {
    const argv = [...opts.fromCommand!, ...passthrough];
    const source = { kind: "command" as const, command: argv[0]!, args: argv.slice(1) };

    // Planned before anything is acquired or started: an invocation this
    // flag cannot support (npx/uvx and friends — see planContainerCommand)
    // should fail without having taken a host-wide lock or built a Docker
    // image on the way to failing.
    let plan;
    try {
      plan = planContainerCommand(argv[0]!, argv.slice(1));
    } catch (err) {
      if (!(err instanceof EnumerationPlanError)) throw err;
      result = { outcome: "never-reached", source, error: err.message, durationMs: 0 };
      await reportUnexaminable(result, opts, logStatus);
      return;
    }

    let lock: ScanLock;
    try {
      lock = await ScanLock.acquire();
    } catch (err) {
      if (!(err instanceof ScanLockHeldError)) throw err;
      // Never-reached, not a separate category: palar did not examine the
      // target, and the reason it didn't is the caller's to see.
      await reportUnexaminable(
        { outcome: "never-reached", source, error: err.message, durationMs: 0 },
        opts,
        logStatus
      );
      return;
    }
    lock.installCrashHandlers();
    if (lock.reclaimed) {
      logStatus(chalk.yellow(`reclaimed a stale live-scan lock (${lock.reclaimed})`));
    }

    try {
      const swept = await sweepOrphanedSandboxState(lock);
      const sweptCount =
        swept.containers.length + swept.networks.length + swept.iptables.length;
      if (sweptCount > 0) {
        logStatus(
          chalk.yellow(
            `reclaimed ${sweptCount} orphaned sandbox object(s) from a previous run ` +
              `that did not tear down cleanly:`
          )
        );
        for (const name of swept.containers) logStatus(chalk.dim(`  container ${name}`));
        for (const name of swept.networks) logStatus(chalk.dim(`  network ${name}`));
        for (const line of swept.iptables) logStatus(chalk.dim(`  iptables ${line}`));
      }

      logStatus(
        chalk.dim(
          `starting ${describeSource(source)} in a sandbox container ` +
            `(mounting ${plan.mountDir} read-only at /target) to enumerate tools...`
        )
      );
      result = await enumerateFromCommand(lock, plan, enumerateOpts);
    } finally {
      await lock.release();
    }
  }

  if (result.outcome !== "enumerated") {
    await reportUnexaminable(result, opts, logStatus);
    return;
  }

  const source = describeSource(result.source);
  const audit = runAudit(
    {
      tools: result.tools.map((definition) => ({ file: source, definition })),
      // No server *definition file* was read, so the server-side rules
      // (network posture, credentials in a manifest) have nothing to
      // evaluate. Reported as 0 servers scanned rather than papered over —
      // a live scan of tool schemas genuinely does not cover them.
      servers: [],
      warnings: [],
    },
    config
  );

  const doc: ScanJsonDocument = { outcome: "examined", ...audit };
  await emitScanOutput(
    opts.json
      ? JSON.stringify(doc, null, 2)
      : `> Definitions enumerated live from ${source} — ` +
          `${result.tools.length} tool(s) in ${result.durationMs}ms, no manifest read.\n\n` +
          renderMarkdownReport(audit),
    opts,
    logStatus
  );

  reportScore(audit, opts, logStatus);
}

/** Prints the one-line score summary and applies --fail-on. */
function reportScore(
  result: AuditResult,
  opts: ScanOpts,
  logStatus: (message: string) => void
): void {
  const { value, grade } = result.score;
  const color = value >= 90 ? chalk.green : value >= 60 ? chalk.yellow : chalk.red;
  logStatus(
    color(
      `score ${value}/100 (${grade}) — ${result.findings.length} finding(s), ` +
        `${result.toolsScanned} tool(s), ${result.serversScanned} server(s)` +
        (result.warnings.length > 0 ? `, ${result.warnings.length} warning(s)` : "")
    )
  );

  if (opts.failOn) {
    const failing = result.findings.filter(
      (f) => severityRank(f.severity) <= severityRank(opts.failOn!)
    ).length;
    if (failing > 0) {
      logStatus(
        chalk.red(`Failing: ${failing} finding(s) at or above '${opts.failOn}' severity`)
      );
      process.exitCode = 1;
    }
  }
}

addLimitOptions(
  program
    .command("scan")
    .description("Scan local MCP definition files and report findings")
  .argument("[paths...]", "files or directories to scan (default: cwd)")
  .option("--dir <dir...>", "additional directories to scan")
  .addOption(
    new Option(
      "--from-url <url>",
      "take tool definitions from a running MCP server over SSE instead of from files on " +
        "disk, then apply the same rules to them. Enumeration only: it calls listTools() " +
        "once and never calls a tool, so it spawns nothing, needs no Docker, and takes no " +
        "lock. SSE endpoints only — a streamable-HTTP URL will not connect"
    ).conflicts(["fromCommand", "dir"])
  )
  .addOption(
    new Option(
      "--from-command <command...>",
      "take tool definitions from a server you already have installed on this disk by " +
        "starting it, then apply the same rules to them. Enumeration only (listTools() once, " +
        "no tool is ever called). The server always runs inside the same Docker container " +
        "sandbox `palar live` uses, with NO permitted network egress at all, and always takes " +
        "the host-wide live-scan lock — neither is optional. LIMITATION: the sandbox provides " +
        "a Node runtime, a read-only mount of the server's own directory, and no network or " +
        "DNS whatsoever. WORKS: a Node server present on this disk, e.g. one you are " +
        "developing (`--from-command node ./dist/index.js`) or an installed package " +
        "(`--from-command node node_modules/@scope/server/dist/index.js`). DOES NOT WORK: " +
        "anything that must be fetched to run (`npx -y @scope/server`, `uvx`, `pipx`) or that " +
        "needs a runtime other than Node (Python, Go, a compiled binary). A token starting " +
        "with `-` ends the list, so pass a target's own flags after a bare `--`: " +
        "`--from-command node ./cli.js -- --headless`"
    ).conflicts(["fromUrl", "dir"])
  )
  .addOption(
    new Option(
      "--from-env <assignment...>",
      "--from-command only: set an environment variable inside the sandbox container, as " +
        "KEY=VALUE (repeatable). Nothing is inherited from this process — a server that stores " +
        "state under $HOME needs `--from-env HOME=/tmp`, since the container's root filesystem " +
        "is read-only and only /tmp is writable"
    ).conflicts(["fromUrl"])
  )
  .option(
    "--connect-timeout-ms <n>",
    "--from-url/--from-command only: how long to wait for the connect/handshake " +
      "(a --from-command target must start a container first, and some servers do work " +
      "before answering `initialize` — desktop-commander takes ~46s)",
    positiveInt,
    90_000
  )
  .option(
    "--timeout-ms <n>",
    "--from-url/--from-command only: hard ceiling for the whole enumeration; keep it above " +
      "--connect-timeout-ms or it preempts that one",
    positiveInt,
    180_000
  )
  .option("--json", "output the raw AuditResult as JSON")
  .option("--out <file>", "write the report to a file instead of stdout")
  .addOption(
    new Option(
      "--fail-on <severity>",
      "exit 1 if any finding is at or above this severity"
    ).choices(SEVERITY_ORDER)
  )
    .option("--fail-on-empty", "exit 1 when no definition files are discovered")
).action(
  async (operands: string[], opts: ScanOpts) => {
      const config = await loadCliConfig(opts);
      const { paths, passthrough } = splitPassthroughOperands(
        operands,
        Boolean(opts.fromCommand)
      );

      if (opts.fromEnv && !opts.fromCommand) {
        throw new InvalidArgumentError(
          "--from-env sets the environment of the server --from-command starts, and there is " +
            "no --from-command here. A file-based scan runs nothing, so it has no environment " +
            "to set."
        );
      }

      if (opts.fromUrl || opts.fromCommand) {
        if (paths.length > 0) {
          throw new InvalidArgumentError(
            "--from-url/--from-command take their definitions from a running server, so they " +
              `cannot be combined with paths to scan (got: ${paths.join(", ")})`
          );
        }
        await scanFromLiveSource(opts, config, passthrough);
        return;
      }

      const roots = [...paths, ...(opts.dir ?? [])];
      const discovered = await discover(roots, {
        maxFileSize: config.limits.maxFileSize,
      });

      // In --json mode stdout carries only the JSON body; status goes to stderr.
      const logStatus = opts.json ? console.error : console.log;

      const nothingFound =
        discovered.tools.length === 0 && discovered.servers.length === 0;
      const where = roots.length > 0 ? roots.join(", ") : process.cwd();

      // Note the missing `&& !opts.json`. With that gate, --json fell
      // through to a real audit of zero definitions and published
      // score 100/100 grade A, exit 0 — a perfect grade for a directory
      // palar never found anything in, which is the single most dangerous
      // thing this tool can say. Same principle as --from-url/--from-command's
      // failure modes: no examination, no score. The exit code is
      // unchanged and still governed by --fail-on-empty, which is the
      // documented opt-in for treating an empty scan as a failure.
      if (nothingFound) {
        logStatus(
          chalk.yellow(
            `No MCP tool or server definition files found under: ${where}`
          )
        );
        // Warnings first, then the generic hint. A named path that does not
        // exist, or that palar declined to read, has a specific reason
        // attached to it — printing the catch-all advice above that reason
        // buries the one line that says what actually happened.
        for (const warning of discovered.warnings) {
          logStatus(chalk.dim(`warning: ${warning}`));
        }
        logStatus(
          chalk.yellow(
            "Check the path, or that files match the expected naming patterns: " +
              "mcp.tools.json, tools/*.json, *.mcp-tools.json, " +
              "mcp.server.json, mcp.config.json, *.mcp-server.json"
          )
        );
        if (opts.json || opts.out) {
          const doc: ScanJsonDocument = {
            outcome: "nothing-discovered",
            timestamp: new Date().toISOString(),
            searched: roots.length > 0 ? roots : [process.cwd()],
            warnings: discovered.warnings,
          };
          await emitScanOutput(
            opts.json
              ? JSON.stringify(doc, null, 2)
              : `# palar audit report\n\n- **Timestamp:** ${doc.timestamp}\n` +
                  `- **Searched:** ${doc.searched.join(", ")}\n` +
                  `- **Outcome:** no definition files discovered — no score\n`,
            opts,
            logStatus
          );
        }
        if (opts.failOnEmpty) {
          logStatus(
            chalk.red(
              `Failing: no MCP tool or server definitions found under ${where} — ` +
                `--fail-on-empty is set`
            )
          );
          process.exitCode = 1;
        }
        return;
      }

      const result = runAudit(discovered, config);
      const doc: ScanJsonDocument = { outcome: "examined", ...result };

      await emitScanOutput(
        opts.json ? JSON.stringify(doc, null, 2) : renderMarkdownReport(result),
        opts,
        logStatus
      );

      reportScore(result, opts, logStatus);
    }
  );

addLimitOptions(
  program
    .command("snapshot")
    .description("Record a baseline of tool definition hashes for drift detection")
    .option("--dir <dir...>", "directories to scan")
    .option("--out <file>", "snapshot file to write", ".palar-snapshot.json")
).action(
  async (opts: { dir?: string[]; out: string } & LimitOpts) => {
    const config = await loadCliConfig(opts);
    const discovered = await discover(opts.dir ?? [], {
      maxFileSize: config.limits.maxFileSize,
    });
    for (const warning of discovered.warnings) {
      console.error(chalk.dim(`warning: ${warning}`));
    }
    const { snapshot, warnings } = buildSnapshot(discovered, config.limits);
    for (const warning of warnings) {
      console.error(chalk.yellow(`warning: ${warning}`));
    }
    await saveSnapshot(opts.out, snapshot);
    console.log(
      chalk.green(
        `snapshot of ${Object.keys(snapshot.tools).length} tool(s) written to ${opts.out}`
      )
    );
  });

program
  .command("drift")
  .description("Compare current tool definitions against a baseline snapshot")
  .option("--dir <dir...>", "directories to scan")
  .option("--snapshot <file>", "baseline snapshot file", ".palar-snapshot.json")
  .option(
    "--config <path>",
    "path to a config file (default: ./.palarrc.json when present)"
  )
  .action(async (opts: { dir?: string[]; snapshot: string; config?: string }) => {
    const config = await loadCliConfig(opts);
    const baseline = await loadSnapshot(opts.snapshot);
    if (!baseline) {
      console.error(
        chalk.red(
          `no usable snapshot at ${opts.snapshot} (missing or malformed) — ` +
            `run "palar snapshot" first to record a baseline`
        )
      );
      process.exitCode = 1;
      return;
    }
    const discovered = await discover(opts.dir ?? []);
    for (const warning of discovered.warnings) {
      console.error(chalk.dim(`warning: ${warning}`));
    }
    const { snapshot: current, warnings } = buildSnapshot(discovered, config.limits);
    for (const warning of warnings) {
      console.error(chalk.yellow(`warning: ${warning}`));
    }
    const diff = diffSnapshotsDetailed(baseline, current);
    if (diff.length === 0) {
      console.log(
        chalk.green(`no drift against ${opts.snapshot} (${baseline.createdAt})`)
      );
      return;
    }
    for (const entry of diff) {
      switch (entry.kind) {
        case "added":
          console.log(chalk.cyan(`added: ${entry.toolName}`));
          break;
        case "removed":
          console.log(chalk.red(`removed: ${entry.toolName}`));
          break;
        case "regressed":
          console.log(
            chalk.red(
              `regressed: ${entry.toolName} — security regression: ${entry.reason}`
            )
          );
          break;
        case "changed":
          console.log(chalk.yellow(`changed: ${entry.toolName}`));
          break;
      }
      for (const change of entry.changes) {
        const color =
          change.classification === "loosening"
            ? chalk.red
            : change.classification === "tightening"
              ? chalk.green
              : chalk.dim;
        console.log(color(`  [${change.classification}] ${change.description}`));
      }
    }
    if (diff.some((entry) => entry.kind !== "added")) {
      process.exitCode = 1;
    }
  });

addLimitOptions(
  program
    .command("live")
    .description(
      "Spawn/connect to discovered MCP servers for real and probe them with an out-of-band " +
        "callback oracle (EXPERIMENTAL — stdio targets run in a Docker container; see --help)"
    )
    .argument("[paths...]", "files or directories to scan (default: cwd)")
    .option("--dir <dir...>", "additional directories to scan")
    .option(
      "--execute",
      "required: confirms you understand this spawns/connects to the target for real " +
        "(stdio targets sandboxed in a Docker container, not a VM — see --help)"
    )
    .option(
      "--timeout-ms <n>",
      "hard ceiling for the whole live scan per server (connect + listTools + every probe); " +
        "keep it above --connect-timeout-ms or it preempts that one",
      positiveInt,
      180_000
    )
    .option(
      "--connect-timeout-ms <n>",
      "how long to wait for the TARGET to answer the MCP handshake. For a stdio target the " +
        "clock starts once its container is running, so palar's own container start is not " +
        "charged to it (see --container-start-timeout-ms). Some servers do real work before " +
        "answering `initialize` — desktop-commander takes ~44-53s",
      positiveInt,
      90_000
    )
    .option(
      "--container-start-timeout-ms <n>",
      "how long to wait for palar's OWN sandbox container to reach a running state, before " +
        "the target's clock starts. This measures this machine's Docker daemon, not the " +
        "server — a warm daemon does it in under 2s, a cold one can take far longer",
      positiveInt,
      120_000
    )
    .option(
      "--callback-timeout-ms <n>",
      "how long to wait for an oracle callback after each probe",
      positiveInt,
      4_000
    )
    .option(
      "--oracle-host <host>",
      "host the callback listener binds to for SSE targets (stdio targets bind to whatever address is actually reachable on this Docker backend, chosen automatically)",
      "127.0.0.1"
    )
    .option("--json", "output raw results as JSON")
    .option("--out <file>", "write the report to a file instead of stdout")
).action(
  async (
    paths: string[],
    opts: {
      dir?: string[];
      execute?: boolean;
      timeoutMs: number;
      connectTimeoutMs: number;
      containerStartTimeoutMs: number;
      callbackTimeoutMs: number;
      oracleHost: string;
      json?: boolean;
      out?: string;
    } & LimitOpts
  ) => {
    // In --json mode stdout carries only the JSON body; status goes to
    // stderr, matching `scan`'s convention so piping stays clean.
    const logStatus = opts.json ? console.error : console.log;

    if (!opts.execute) {
      logStatus(
        chalk.yellow(
          "palar live: refusing to run without --execute.\n\n" +
            "This command spawns each discovered server's declared command as a real process " +
            "(or connects to it over SSE) and sends it real crafted input. stdio targets run " +
            "inside an ephemeral, network-restricted Docker container (mounted read-only, " +
            "capabilities dropped, resource-limited) — Docker is required, with no unsandboxed " +
            "fallback. That is container isolation, not a VM or gVisor: a kernel-level " +
            "container escape is not mitigated, and SSE targets (no local process to sandbox) " +
            "are unaffected. See README.md's \"Live scanning\" section for the full list of " +
            "what is and isn't covered.\n\n" +
            "Re-run with --execute once you understand and accept that."
        )
      );
      process.exitCode = 1;
      return;
    }

    // The two ceilings interact rather than add: --timeout-ms races the
    // whole scan, so if it isn't larger than --connect-timeout-ms it
    // preempts it and the connect timeout never gets to apply. Warned
    // rather than rejected — a deliberately tiny overall budget is a
    // legitimate thing to ask for, it just shouldn't look like the connect
    // timeout is what's being honored.
    if (opts.connectTimeoutMs >= opts.timeoutMs) {
      logStatus(
        chalk.yellow(
          `warning: --connect-timeout-ms (${opts.connectTimeoutMs}) is not below --timeout-ms ` +
            `(${opts.timeoutMs}), which bounds the entire scan — the overall ceiling will fire ` +
            `first and the connect timeout will never apply`
        )
      );
    }

    // Before the sweep, and before anything creates sandbox state: take the
    // host-wide live-scan lock. This is what makes the sweep below safe —
    // holding it means no other palar live scan can be running, so every
    // mcpg-/MCPG- object on the daemon really is an orphan rather than
    // possibly a concurrent scan's live state. See lock.ts.
    let lock: ScanLock;
    try {
      lock = await ScanLock.acquire();
    } catch (err) {
      if (err instanceof ScanLockHeldError) {
        logStatus(chalk.yellow(`palar live: ${err.message}`));
        process.exitCode = 1;
        return;
      }
      throw err;
    }
    lock.installCrashHandlers();
    if (lock.reclaimed) {
      logStatus(
        chalk.yellow(`reclaimed a stale live-scan lock (${lock.reclaimed})`)
      );
    }

    try {
      // Reclaim sandbox leftovers from a previous run that never reached
      // teardown (crash, kill, Ctrl-C). Reported rather than silent — a live
      // container or a stray netfilter jump surviving a crash is worth the
      // user knowing about, not something to clean up behind their back.
      // Passing the lock is the point, not ceremony: the sweep's signature
      // requires one, so this call is the compiler's proof that the
      // wildcard reclaim below can only ever be looking at orphans.
      const swept = await sweepOrphanedSandboxState(lock);
      const sweptCount =
        swept.containers.length + swept.networks.length + swept.iptables.length;
      if (sweptCount > 0) {
        logStatus(
          chalk.yellow(
            `reclaimed ${sweptCount} orphaned sandbox object(s) from a previous run ` +
              `that did not tear down cleanly:`
          )
        );
        for (const name of swept.containers) logStatus(chalk.dim(`  container ${name}`));
        for (const name of swept.networks) logStatus(chalk.dim(`  network ${name}`));
        for (const line of swept.iptables) logStatus(chalk.dim(`  iptables ${line}`));
      }

      const config = await loadCliConfig(opts);
      const roots = [...paths, ...(opts.dir ?? [])];
      const discovered = await discover(roots, { maxFileSize: config.limits.maxFileSize });
      for (const warning of discovered.warnings) {
        console.error(chalk.dim(`warning: ${warning}`));
      }

      if (discovered.servers.length === 0) {
        logStatus(
          chalk.yellow(
            `No MCP server definition files found under: ${roots.length > 0 ? roots.join(", ") : process.cwd()}`
          )
        );
        return;
      }

      const staticResult = runAudit(discovered, config);
      let anyConfirmed = false;
      const liveResults: Awaited<ReturnType<typeof runLiveScan>>[] = [];

      for (const { file, config: server } of discovered.servers) {
        logStatus(chalk.dim(`connecting to "${server.name}" (${server.transport ?? "stdio"})...`));
        const live = await runLiveScan(server, discovered.tools, {
          targetDir: dirname(file),
          overallTimeoutMs: opts.timeoutMs,
          connectTimeoutMs: opts.connectTimeoutMs,
          containerStartTimeoutMs: opts.containerStartTimeoutMs,
          callbackTimeoutMs: opts.callbackTimeoutMs,
          oracleHost: opts.oracleHost,
          // First run only, and otherwise entirely silent for minutes.
          onImageBuild: (image) =>
            logStatus(
              chalk.yellow(
                `building the sandbox image ${image} — first run only. This fetches a base ` +
                  `image and can take several minutes; it is palar setting itself up, not ` +
                  `the target being slow, and it is not bounded by --timeout-ms.`
              )
            ),
        });

        if (live.probes.some((p) => p.status === "confirmed")) anyConfirmed = true;
        liveResults.push(live);
      }

      // Escalation happens here — after every server has been probed, and
      // before anything is rendered, scored on, or gated on. A confirmed
      // callback is evidence about the finding itself, not a presentation
      // detail, so it has to reach the result --json emits and --fail-on
      // reads, not only the Markdown. Rendering therefore moves out of the
      // loop above: the escalated result is global to the run, and one
      // finding must not read critical in one server's report and medium
      // in the next.
      const escalated = escalateConfirmedFindings(staticResult, liveResults);
      const countCritical = (r: typeof staticResult): number =>
        r.findings.filter((f) => f.severity === "critical").length;
      const escalations = countCritical(escalated) - countCritical(staticResult);
      if (escalations > 0) {
        logStatus(
          chalk.red(
            `${escalations} finding(s) escalated to CRITICAL by a confirmed oracle callback ` +
              `(score recomputed: ${staticResult.score.value} -> ${escalated.score.value})`
          )
        );
      }

      // How much of this run actually spoke to a target. Reaching one is
      // the only thing that makes a live verdict meaningful, so it is
      // computed once here and drives the document shape, the status lines
      // and the exit code alike rather than being re-derived three times.
      const unreached = liveResults.filter((live) => live.outcome !== "probed");
      const reachedAny = unreached.length < liveResults.length;

      const reports = opts.json
        ? []
        : liveResults.map((live) => renderLiveMarkdownReport(escalated, live));

      // One JSON document for the whole run (never multiple concatenated
      // objects, even with several discovered servers) so --json output stays
      // parseable by a single JSON.parse().
      //
      // The `outcome` field is additive on the shape that already existed;
      // the score is not. When NOT ONE target was reached, the emitted
      // static result carries no `score` at all — the same rule
      // ScanJsonDocument states, for the same reason. `palar live`'s whole
      // claim is about what a running server does, and a run that spoke to
      // no running server has no verdict to summarise into a grade. The
      // findings stay: they are observations about files palar really did
      // read, and they stand on their own. A grade does not, because a CI
      // job reads a grade as the answer to "did this pass?" — and 85/B for
      // a target that never started is that question answered wrong.
      const document = reachedAny
        ? {
            outcome: unreached.length > 0 ? ("partial" as const) : ("probed" as const),
            static: escalated,
            live: liveResults,
          }
        : {
            outcome: "never-reached" as const,
            static: { ...escalated, score: undefined },
            live: liveResults,
          };
      const output = opts.json
        ? JSON.stringify(document, null, 2)
        : reports.join("\n");

      if (opts.out) {
        await writeFile(opts.out, output, "utf8");
        logStatus(chalk.dim(`report written to ${opts.out}`));
      } else {
        console.log(output);
      }

      // Every unreached target is named on its own line, whatever the exit
      // code turns out to be. On a mixed run the code is decided by the
      // servers that DID answer, and without this the ones that did not
      // would be visible only to a reader of the full report — which is how
      // a target that silently produced nothing stays silent.
      for (const live of unreached) {
        logStatus(
          chalk.red(
            live.outcome === "never-reached"
              ? `NEVER REACHED "${live.serverName}": ${live.unreachable?.reason ?? "unknown reason"}`
              : `NO TOOLS from "${live.serverName}": it completed the MCP handshake and ` +
                  "reported zero tools, so there was nothing to probe."
          )
        );
      }

      // Exit codes, in precedence order. A confirmed finding outranks
      // everything: it is a result, and a result beats a report about
      // coverage.
      //
      //   1 — something was CONFIRMED by an oracle callback.
      //   2 — palar examined nothing. Three ways to arrive here, all the
      //       same event: no target was reached at all, every target that
      //       was reached exposed zero tools, or probes were attempted and
      //       every one of them was NOT TESTED. Same category as `scan`'s
      //       never-reached and given the same code for the same reason —
      //       a scan that examined nothing must not exit 0 alongside a
      //       scan that examined everything and found it clean.
      //   0 — at least one target was reached and probing really happened.
      //       Partial coverage is a warning, not a failure: whatever did
      //       run really ran, and its findings stand.
      //
      // 2 was already this command's "nothing was learned" code, so the
      // never-reached case widens a meaning that already exists rather than
      // claiming a new number. The code that could NOT be reused is 1: in
      // `scan` it means "reached, zero tools", and here it means "something
      // was CONFIRMED". Those are separate commands with separate
      // contracts, and `live`'s 1 is the load-bearing one for a CI gate —
      // so `live` folds its own zero-tools case into 2 rather than matching
      // `scan`'s numbering and turning a coverage gap into a confirmation.
      const allProbes = liveResults.flatMap((live) => live.probes);
      const notTested = allProbes.filter((p) => p.status === "not-tested");

      if (anyConfirmed) {
        logStatus(
          chalk.red("Failing: at least one finding was CONFIRMED via oracle callback")
        );
        process.exitCode = 1;
      } else if (!reachedAny) {
        process.exitCode = 2;
        logStatus(
          chalk.red(
            `Failing: palar reached none of the ${liveResults.length} discovered server(s), so ` +
              `no tool was exercised and no probe was sent. No score is reported: palar ` +
              `examined nothing, which is not the same as finding nothing. The static findings ` +
              `describe the definition FILES only — they say nothing about the running server, ` +
              `which is the only thing this command exists to check.`
          )
        );
      } else if (allProbes.length > 0 && notTested.length === allProbes.length) {
        process.exitCode = 2;
        logStatus(
          chalk.red(
            `Failing: all ${allProbes.length} probe(s) were NOT TESTED — every call failed with ` +
              `palar's own arguments already violating the target's declared schema, so no ` +
              `field was exercised and nothing was learned. This is not a clean result; it is ` +
              `no result. See the NOT TESTED section for the constraints palar could not satisfy.`
          )
        );
      } else if (notTested.length > 0) {
        logStatus(
          chalk.yellow(
            `warning: ${notTested.length} of ${allProbes.length} probe(s) were NOT TESTED — ` +
              `palar's arguments violated the target's declared schema, so those fields were ` +
              `never exercised. Their static findings remain unverified.`
          )
        );
      }
    } finally {
      // Same unconditional-teardown rigor as the sandbox's own container /
      // network / firewall cleanup: the lock is released on success,
      // failure and timeout alike, including the early `return` above. The
      // abrupt paths that skip this `finally` entirely (Ctrl-C, SIGTERM)
      // are covered by the crash handlers installed above; SIGKILL is
      // covered by the next run's stale-lock detection.
      await lock.release();
    }
  }
);

try {
  await program.parseAsync();
} catch (err) {
  console.error(chalk.red(`palar: ${(err as Error).message}`));
  process.exitCode = 1;
}
