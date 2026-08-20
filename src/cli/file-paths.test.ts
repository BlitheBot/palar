/**
 * End-to-end guards on `palar scan <file.json>`.
 *
 * `--help` has documented "files or directories to scan" since the command
 * existed, and a file never worked: fast-glob takes each root as its `cwd`,
 * so a file root threw `ENOTDIR: not a directory, scandir <path>`. That
 * escaped to the CLI's top-level catch, printed as a bare errno, and then
 * exited 0 — a documented invocation crashing and reporting success, which
 * a CI gate reads as a pass.
 *
 * These run the built binary rather than calling discover() directly,
 * because the exit code is half of what went wrong.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const CLI = join(PACKAGE_ROOT, "dist", "cli", "index.js");

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(args: string[]): Promise<Run> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [CLI, ...args],
      { env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" } },
      (err, stdout, stderr) => {
        resolve({
          code: err ? ((err as NodeJS.ErrnoException & { code?: number }).code ?? 1) : 0,
          stdout,
          stderr,
        });
      }
    );
  });
}

const TOOLS = JSON.stringify([
  {
    name: "run_command",
    description: "Runs a command.",
    inputSchema: { type: "object", properties: { command: { type: "string" } } },
  },
]);

async function fixtureDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "palar-file-scan-"));
  await writeFile(join(dir, "mcp.tools.json"), TOOLS, "utf8");
  await writeFile(
    join(dir, "mcp.server.json"),
    JSON.stringify({ name: "t", transport: "stdio", command: "node", args: ["x.js"] }),
    "utf8"
  );
  await writeFile(join(dir, "notes.json"), TOOLS, "utf8");
  return dir;
}

test("scan of a tool definition file reads it instead of throwing ENOTDIR", async () => {
  const dir = await fixtureDir();
  try {
    const { code, stdout, stderr } = await runCli(["scan", join(dir, "mcp.tools.json"), "--json"]);

    assert.doesNotMatch(stderr, /ENOTDIR/, `scan still crashed on a file root: ${stderr}`);
    const doc = JSON.parse(stdout) as Record<string, unknown>;
    assert.equal(doc.outcome, "examined");
    assert.equal(doc.toolsScanned, 1);
    // The file names tools, not a server, so nothing should be audited as one.
    assert.equal(doc.serversScanned, 0);
    assert.equal(code, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scan of a server definition file audits it as a server", async () => {
  const dir = await fixtureDir();
  try {
    const { stdout } = await runCli(["scan", join(dir, "mcp.server.json"), "--json"]);
    const doc = JSON.parse(stdout) as Record<string, unknown>;
    assert.equal(doc.serversScanned, 1);
    assert.equal(doc.toolsScanned, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a named file matching no definition pattern is refused by name, not by errno", async () => {
  const dir = await fixtureDir();
  try {
    const { code, stdout, stderr } = await runCli(["scan", join(dir, "notes.json"), "--json"]);

    assert.doesNotMatch(stderr, /ENOTDIR|ENOENT/);
    // The refusal has to say which file and why, and name the patterns that
    // would have worked — the whole complaint about the old behaviour was
    // that a raw errno tells the reader nothing actionable.
    assert.match(stderr, /notes\.json/);
    assert.match(stderr, /matches no MCP definition pattern/);
    assert.match(stderr, /mcp\.tools\.json/);

    // Nothing was read, so nothing is scored. Same rule as an empty scan.
    const doc = JSON.parse(stdout) as Record<string, unknown>;
    assert.equal(doc.outcome, "nothing-discovered");
    assert.equal("score" in doc, false);
    assert.equal(code, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a scan path that does not exist says so rather than silently finding nothing", async () => {
  const dir = await fixtureDir();
  try {
    const missing = join(dir, "definitely-not-here.json");
    const { code, stderr } = await runCli(["scan", missing, "--json"]);

    assert.match(stderr, /definitely-not-here\.json: cannot be scanned/);
    assert.match(stderr, /ENOENT/);
    // Still governed by --fail-on-empty, which is the documented opt-in.
    assert.equal(code, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a file root and a directory root can be mixed in one scan", async () => {
  const dir = await fixtureDir();
  try {
    const { stdout } = await runCli([
      "scan",
      join(dir, "mcp.tools.json"),
      dir,
      "--json",
    ]);
    const doc = JSON.parse(stdout) as Record<string, unknown>;
    // The directory finds the same tools file the explicit root names, and
    // it must be audited once, not twice.
    assert.equal(doc.toolsScanned, 1);
    assert.equal(doc.serversScanned, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
