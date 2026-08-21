// Demo runner for fixtures/vuln-server: starts the intentionally-vulnerable
// server over stdio to prove it is real and running, then runs Palar's
// static scan against its definition files. Combined output goes to stdout;
// redirect it if you want a file.
//
// Note: Palar is a read-only static analyzer — it audits local
// mcp.tools.json / mcp.server.json files, it does not itself speak MCP to a
// live server. The stdio smoke test and the static scan are therefore two
// separate steps below, not one.
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const TSX_CLI = new URL("../node_modules/tsx/dist/cli.mjs", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const VULN_SERVER_ENTRY = "fixtures/vuln-server/src/index.ts";
const FIXTURE_DIR = "fixtures/vuln-server";

function writeSection(title) {
  process.stdout.write(`\n=== ${title} ===\n`);
}

async function smokeTestLiveServer() {
  writeSection("1. Live stdio smoke test (fixtures/vuln-server)");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [TSX_CLI, VULN_SERVER_ENTRY],
  });
  const client = new Client({ name: "palar-demo-client", version: "0.1.0" });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    process.stdout.write(`connected over stdio; server reports ${tools.length} tool(s):\n`);
    for (const tool of tools) {
      process.stdout.write(`  - ${tool.name}\n`);
    }
  } finally {
    await client.close();
  }
}

function runStaticScan() {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [TSX_CLI, "src/cli/index.ts", "scan", FIXTURE_DIR],
      { stdio: ["ignore", "pipe", "pipe"] }
    );

    child.stdout.on("data", (chunk) => {
      process.stdout.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      process.stderr.write(chunk);
    });

    child.on("error", reject);
    child.on("close", (code) => resolve(code ?? 0));
  });
}

async function main() {
  await smokeTestLiveServer();
  writeSection("2. Palar static scan (palar scan fixtures/vuln-server)");
  const scanExitCode = await runStaticScan();
  writeSection("done");
  process.exitCode = scanExitCode;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
