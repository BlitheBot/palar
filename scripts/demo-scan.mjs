// Demo runner for fixtures/vuln-server: starts the intentionally-vulnerable
// server over stdio to prove it is real and running, then runs MCPGuard's
// static scan against its definition files. Combined output is written to
// stdout and to demo/scan-output.log.
//
// Note: MCPGuard is a read-only static analyzer — it audits local
// mcp.tools.json / mcp.server.json files, it does not itself speak MCP to a
// live server. The stdio smoke test and the static scan are therefore two
// separate steps below, not one.
import { spawn } from "node:child_process";
import { mkdir, open } from "node:fs/promises";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const TSX_CLI = new URL("../node_modules/tsx/dist/cli.mjs", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1");
const VULN_SERVER_ENTRY = "fixtures/vuln-server/src/index.ts";
const FIXTURE_DIR = "fixtures/vuln-server";
const LOG_PATH = "demo/scan-output.log";

async function writeSection(logHandle, title) {
  const banner = `\n=== ${title} ===\n`;
  process.stdout.write(banner);
  await logHandle.write(banner);
}

async function tee(logHandle, text) {
  process.stdout.write(text);
  await logHandle.write(text);
}

async function smokeTestLiveServer(logHandle) {
  await writeSection(logHandle, "1. Live stdio smoke test (fixtures/vuln-server)");
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [TSX_CLI, VULN_SERVER_ENTRY],
  });
  const client = new Client({ name: "mcpguard-demo-client", version: "0.1.0" });
  try {
    await client.connect(transport);
    const { tools } = await client.listTools();
    await tee(
      logHandle,
      `connected over stdio; server reports ${tools.length} tool(s):\n`
    );
    for (const tool of tools) {
      await tee(logHandle, `  - ${tool.name}\n`);
    }
  } finally {
    await client.close();
  }
}

function runStaticScan(logHandle) {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      [TSX_CLI, "src/cli/index.ts", "scan", FIXTURE_DIR],
      { stdio: ["ignore", "pipe", "pipe"] }
    );

    child.stdout.on("data", (chunk) => {
      process.stdout.write(chunk);
      logHandle.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      process.stderr.write(chunk);
      logHandle.write(chunk);
    });

    child.on("error", reject);
    child.on("close", (code) => resolve(code ?? 0));
  });
}

async function main() {
  await mkdir("demo", { recursive: true });
  const logHandle = await open(LOG_PATH, "w");
  try {
    await smokeTestLiveServer(logHandle);
    await writeSection(logHandle, "2. MCPGuard static scan (mcpguard scan fixtures/vuln-server)");
    const scanExitCode = await runStaticScan(logHandle);
    await writeSection(logHandle, `done — log written to ${LOG_PATH}`);
    process.exitCode = scanExitCode;
  } finally {
    await logHandle.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
