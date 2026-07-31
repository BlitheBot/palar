#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { Command, InvalidArgumentError, Option } from "commander";
import chalk from "chalk";
import type { Severity } from "../core/types.js";
import type { ResolvedConfig } from "../core/config.js";
import { DEFAULT_LIMITS, loadConfigFile } from "../core/config.js";
import { discover } from "../discovery/index.js";
import { runAudit } from "../core/auditor.js";
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
import { sweepOrphanedSandboxState } from "../live/sandbox.js";
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
 * Load config from --config / .mcpguardrc.json (defaults when absent),
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
    "path to a config file (default: ./.mcpguardrc.json when present)"
  );
  for (const [flag, description] of LIMIT_OPTIONS) {
    cmd.option(flag, description, positiveInt);
  }
  return cmd;
}

program
  .name("mcpguard")
  .description(
    "Read-only static analyzer for local MCP tool and server definition files"
  )
  .version("0.1.0");

addLimitOptions(
  program
    .command("scan")
    .description("Scan local MCP definition files and report findings")
  .argument("[paths...]", "files or directories to scan (default: cwd)")
  .option("--dir <dir...>", "additional directories to scan")
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
  async (
    paths: string[],
    opts: {
      dir?: string[];
      json?: boolean;
      out?: string;
      failOn?: Severity;
      failOnEmpty?: boolean;
    } & LimitOpts
  ) => {
      const config = await loadCliConfig(opts);
      const roots = [...paths, ...(opts.dir ?? [])];
      const discovered = await discover(roots, {
        maxFileSize: config.limits.maxFileSize,
      });

      const nothingFound =
        discovered.tools.length === 0 && discovered.servers.length === 0;
      const where = roots.length > 0 ? roots.join(", ") : process.cwd();
      const failEmpty = () => {
        console[opts.json ? "error" : "log"](
          chalk.red(
            `Failing: no MCP tool or server definitions found under ${where} — ` +
              `--fail-on-empty is set`
          )
        );
        process.exitCode = 1;
      };
      if (nothingFound && !opts.json) {
        console.log(
          chalk.yellow(
            `No MCP tool or server definition files found under: ${where}`
          )
        );
        console.log(
          chalk.yellow(
            "Check the path, or that files match the expected naming patterns: " +
              "mcp.tools.json, tools/*.json, *.mcp-tools.json, " +
              "mcp.server.json, mcp.config.json, *.mcp-server.json"
          )
        );
        for (const warning of discovered.warnings) {
          console.log(chalk.dim(`warning: ${warning}`));
        }
        if (opts.failOnEmpty) failEmpty();
        return;
      }

      const result = runAudit(discovered, config);

      const output = opts.json
        ? JSON.stringify(result, null, 2)
        : renderMarkdownReport(result);

      // In --json mode stdout carries only the JSON body; status goes to stderr.
      const logStatus = opts.json ? console.error : console.log;

      if (opts.out) {
        await writeFile(opts.out, output, "utf8");
        logStatus(chalk.dim(`report written to ${opts.out}`));
      } else {
        console.log(output);
      }

      const { value, grade } = result.score;
      const color =
        value >= 90 ? chalk.green : value >= 60 ? chalk.yellow : chalk.red;
      logStatus(
        color(
          `score ${value}/100 (${grade}) — ${result.findings.length} finding(s), ` +
            `${result.toolsScanned} tool(s), ${result.serversScanned} server(s)` +
            (result.warnings.length > 0
              ? `, ${result.warnings.length} warning(s)`
              : "")
        )
      );

      if (opts.failOn) {
        const failing = result.findings.filter(
          (f) => severityRank(f.severity) <= severityRank(opts.failOn!)
        ).length;
        if (failing > 0) {
          logStatus(
            chalk.red(
              `Failing: ${failing} finding(s) at or above '${opts.failOn}' severity`
            )
          );
          process.exitCode = 1;
        }
      }

      if (opts.failOnEmpty && nothingFound) failEmpty();
    }
  );

addLimitOptions(
  program
    .command("snapshot")
    .description("Record a baseline of tool definition hashes for drift detection")
    .option("--dir <dir...>", "directories to scan")
    .option("--out <file>", "snapshot file to write", ".mcpguard-snapshot.json")
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
  .option("--snapshot <file>", "baseline snapshot file", ".mcpguard-snapshot.json")
  .option(
    "--config <path>",
    "path to a config file (default: ./.mcpguardrc.json when present)"
  )
  .action(async (opts: { dir?: string[]; snapshot: string; config?: string }) => {
    const config = await loadCliConfig(opts);
    const baseline = await loadSnapshot(opts.snapshot);
    if (!baseline) {
      console.error(
        chalk.red(
          `no usable snapshot at ${opts.snapshot} (missing or malformed) — ` +
            `run "mcpguard snapshot" first to record a baseline`
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
    .option("--timeout-ms <n>", "hard ceiling for the whole live scan per server", positiveInt, 60_000)
    .option(
      "--connect-timeout-ms <n>",
      "how long to wait for a target's connect/handshake (stdio targets must start a container first)",
      positiveInt,
      30_000
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
          "mcpguard live: refusing to run without --execute.\n\n" +
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

    // Before anything else creates state of its own: reclaim sandbox
    // leftovers from a previous run that never reached teardown (crash,
    // kill, Ctrl-C). Reported rather than silent — a live container or a
    // stray netfilter jump surviving a crash is worth the user knowing
    // about, not something to clean up behind their back.
    const swept = await sweepOrphanedSandboxState();
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
    const reports: string[] = [];

    for (const { file, config: server } of discovered.servers) {
      logStatus(chalk.dim(`connecting to "${server.name}" (${server.transport ?? "stdio"})...`));
      const live = await runLiveScan(server, discovered.tools, {
        targetDir: dirname(file),
        overallTimeoutMs: opts.timeoutMs,
        connectTimeoutMs: opts.connectTimeoutMs,
        callbackTimeoutMs: opts.callbackTimeoutMs,
        oracleHost: opts.oracleHost,
      });

      if (live.probes.some((p) => p.status === "confirmed")) anyConfirmed = true;
      liveResults.push(live);
      if (!opts.json) reports.push(renderLiveMarkdownReport(staticResult, live));
    }

    // One JSON document for the whole run (never multiple concatenated
    // objects, even with several discovered servers) so --json output stays
    // parseable by a single JSON.parse().
    const output = opts.json
      ? JSON.stringify({ static: staticResult, live: liveResults }, null, 2)
      : reports.join("\n");

    if (opts.out) {
      await writeFile(opts.out, output, "utf8");
      logStatus(chalk.dim(`report written to ${opts.out}`));
    } else {
      console.log(output);
    }

    if (anyConfirmed) {
      logStatus(
        chalk.red("Failing: at least one finding was CONFIRMED via oracle callback")
      );
      process.exitCode = 1;
    }
  }
);

try {
  await program.parseAsync();
} catch (err) {
  console.error(chalk.red(`mcpguard: ${(err as Error).message}`));
  process.exitCode = 1;
}
