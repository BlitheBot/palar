/**
 * Guards against the CLI's reported version drifting from package.json.
 *
 * palar 0.2.0 was published with the binary still reporting "0.1.0" from a
 * hardcoded literal. The end-to-end assertion below (actually running the
 * built CLI with --version) is the one that would have caught it; the unit
 * assertions cover the reader itself.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readPackageVersion, VERSION } from "../core/version.js";

const execFileAsync = promisify(execFile);

// dist/cli/ -> package root
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const packageVersion = (
  JSON.parse(readFileSync(join(PACKAGE_ROOT, "package.json"), "utf8")) as { version: string }
).version;

test("the exported VERSION matches package.json's version field", () => {
  assert.equal(VERSION, packageVersion);
});

test("readPackageVersion reads the real package.json", () => {
  assert.equal(readPackageVersion(), packageVersion);
  assert.match(VERSION, /^\d+\.\d+\.\d+/);
});

test("readPackageVersion throws rather than guessing when version is missing", () => {
  // A wrong version is worse than a missing one: it misreports instead of
  // failing, which is how 0.1.0 shipped inside 0.2.0.
  assert.throws(() => readPackageVersion(join(PACKAGE_ROOT, "src")), /no usable "version" field|ENOENT/);
});

test("`palar --version` prints exactly package.json's version", async () => {
  // The real end-to-end check: spawn the built binary the way a user would.
  const cliPath = join(PACKAGE_ROOT, "dist", "cli", "index.js");
  const { stdout } = await execFileAsync(process.execPath, [cliPath, "--version"]);
  assert.equal(
    stdout.trim(),
    packageVersion,
    `\`palar --version\` printed "${stdout.trim()}" but package.json says "${packageVersion}" — ` +
      "the CLI's version has drifted from the package's"
  );
});
