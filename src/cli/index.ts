#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
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

try {
  await program.parseAsync();
} catch (err) {
  console.error(chalk.red(`mcpguard: ${(err as Error).message}`));
  process.exitCode = 1;
}
