/**
 * The CLI's version, read from package.json at runtime rather than
 * duplicated as a literal.
 *
 * A hardcoded string here drifts silently the moment package.json is
 * bumped: 0.2.0 was published with the binary still reporting "0.1.0",
 * which is the exact bug this module exists to make impossible. Deliberately
 * NOT given a fallback default — a version string that is wrong is worse
 * than one that is missing, because it misreports rather than fails, and
 * misreporting is what went wrong the first time.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

// dist/core/ -> the package root, in the published layout and in the source
// tree alike (npm always includes package.json in the tarball, whether or
// not it is listed in "files").
const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export function readPackageVersion(packageRoot: string = PACKAGE_ROOT): string {
  const raw = readFileSync(join(packageRoot, "package.json"), "utf8");
  const parsed = JSON.parse(raw) as { version?: unknown };
  if (typeof parsed.version !== "string" || parsed.version.length === 0) {
    throw new Error(`package.json at ${packageRoot} has no usable "version" field`);
  }
  return parsed.version;
}

export const VERSION: string = readPackageVersion();
