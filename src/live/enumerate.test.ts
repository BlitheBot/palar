/**
 * Tests for the `--from-command` planner and the enumeration contract.
 *
 * The planner is where `--from-command`'s honesty lives. Its docstring
 * claims a specific set of invocations work and another set does not; these
 * tests pin both halves, because the failure mode of getting the second
 * half wrong is a container that starts, cannot fetch anything, and reports
 * as a connect timeout — a broken-looking target instead of an unsupported
 * invocation.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, sep } from "node:path";
import {
  classifyRuntime,
  describeSource,
  enumerateFromCommand,
  EnumerationPlanError,
  findPlatformMismatches,
  planContainerCommand,
  toToolDefinitions,
  type EnumerationResult,
} from "./enumerate.js";
import { ScanLock, type ProcessProbe } from "./lock.js";

const aliveProbe: ProcessProbe = async (pid) =>
  pid === process.pid ? { alive: true, startedAt: "self-start" } : { alive: false };

async function projectFixture(): Promise<string> {
  // <root>/node_modules/@scope/server/dist/index.js plus a project-level
  // package.json — the layout an installed MCP server actually has.
  const root = await mkdtemp(join(tmpdir(), "palar-plan-test-"));
  const pkgDir = join(root, "node_modules", "@scope", "server", "dist");
  await mkdir(pkgDir, { recursive: true });
  await writeFile(join(pkgDir, "index.js"), "// server\n", "utf8");
  await writeFile(join(root, "package.json"), '{"name":"fixture"}', "utf8");
  return root;
}

test("plans an installed package: mounts the node_modules root, not the package dir", async () => {
  const root = await projectFixture();
  try {
    const plan = planContainerCommand(
      "node",
      ["node_modules/@scope/server/dist/index.js"],
      root
    );

    // The whole point of walking up past node_modules: the package's own
    // dependencies are siblings under <root>/node_modules, so mounting the
    // package directory would produce a container where the program exists
    // and nothing it imports does.
    assert.equal(plan.mountDir, root);
    assert.equal(plan.command, "node");
    assert.deepEqual(plan.args, ["/target/node_modules/@scope/server/dist/index.js"]);
    assert.equal(plan.programPath, join(root, "node_modules", "@scope", "server", "dist", "index.js"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("plans a locally developed server: mounts the project root above dist/", async () => {
  const root = await mkdtemp(join(tmpdir(), "palar-plan-dev-"));
  try {
    await mkdir(join(root, "dist"), { recursive: true });
    await writeFile(join(root, "dist", "index.js"), "// server\n", "utf8");
    await writeFile(join(root, "package.json"), '{"name":"dev"}', "utf8");

    const plan = planContainerCommand("node", ["./dist/index.js"], root);
    assert.equal(plan.mountDir, root);
    assert.deepEqual(plan.args, ["/target/dist/index.js"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("mounts the parent of the OUTERMOST node_modules, not a nested one", async () => {
  const root = await mkdtemp(join(tmpdir(), "palar-plan-nested-"));
  try {
    const nested = join(root, "node_modules", "a", "node_modules", "b", "dist");
    await mkdir(nested, { recursive: true });
    await writeFile(join(nested, "index.js"), "// server\n", "utf8");

    const plan = planContainerCommand(
      "node",
      ["node_modules/a/node_modules/b/dist/index.js"],
      root
    );
    assert.equal(plan.mountDir, root);
    assert.deepEqual(plan.args, [
      "/target/node_modules/a/node_modules/b/dist/index.js",
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rewrites only paths inside the mount; flags and container paths pass through", async () => {
  const root = await projectFixture();
  try {
    const plan = planContainerCommand(
      "node",
      ["node_modules/@scope/server/dist/index.js", "--headless", "/tmp/allowed"],
      root
    );
    assert.equal(plan.args[1], "--headless");
    // A path that is not inside the mount means the container's own path,
    // and must be left exactly as written — rewriting it would silently
    // redirect the target at something else.
    assert.equal(plan.args[2], "/tmp/allowed");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("npx of an uninstalled package is refused with the network/registry reason", () => {
  // npx IS Node, so it passes the runtime gate — but the package it names
  // is not on disk, and the sandbox has no network to fetch it. That is the
  // registry-fetch refusal, not a runtime one.
  for (const argv of [
    ["npx", "-y", "@scope/some-server"],
    ["npx", "mcp-server-fetch"],
  ]) {
    assert.throws(
      () => planContainerCommand(argv[0]!, argv.slice(1), tmpdir()),
      (err: unknown) => {
        assert.ok(err instanceof EnumerationPlanError);
        assert.match((err as Error).message, /already have installed/);
        return true;
      },
      `expected \`${argv.join(" ")}\` to be refused at plan time`
    );
  }
});

test("an unsupported runtime is refused at plan time, named, before any file lookup", () => {
  // These name a non-Node runtime the sandbox image does not have. The
  // refusal must NAME the runtime and point at --from-url — and it must not
  // depend on whether a file exists (the `python <existing.py>` case is
  // exactly the one that used to start a container and hang).
  const cases: [string[], RegExp][] = [
    [["python", "-m", "mcp_server_fetch"], /Python MCP servers aren't supported/],
    [["python", "/etc/hostname"], /Python MCP servers aren't supported/], // file exists, still refused on runtime
    [["uvx", "mcp-server-git"], /Python \(uvx\) MCP servers aren't supported/],
    [["uv", "run", "server"], /Python \(uv\) MCP servers aren't supported/],
    [["go", "run", "./main.go"], /Go MCP servers aren't supported/],
    [["deno", "run", "server.ts"], /Deno MCP servers aren't supported/],
  ];
  for (const [argv, pattern] of cases) {
    assert.throws(
      () => planContainerCommand(argv[0]!, argv.slice(1), tmpdir()),
      (err: unknown) => {
        assert.ok(err instanceof EnumerationPlanError);
        assert.match((err as Error).message, pattern);
        assert.match((err as Error).message, /Node-only/);
        assert.match((err as Error).message, /scan --from-url/);
        return true;
      },
      `expected \`${argv.join(" ")}\` to be refused by runtime at plan time`
    );
  }
});

test("a non-Node binary path and an unrecognised bare name both refuse, failing toward refusal", () => {
  assert.throws(
    () => planContainerCommand("/usr/local/bin/mcp-server", [], tmpdir()),
    (err: unknown) =>
      err instanceof EnumerationPlanError && /non-Node binary or script/.test((err as Error).message),
    "a bare binary path must refuse"
  );
  assert.throws(
    () => planContainerCommand("mcp-server", ["stdio"], tmpdir()),
    (err: unknown) =>
      err instanceof EnumerationPlanError && /could not recognise the runtime/.test((err as Error).message),
    "an unrecognised bare name must refuse rather than assume Node"
  );
});

test("classifyRuntime: node/npx supported, interpreters/binaries not, Node scripts ok", () => {
  assert.deepEqual(classifyRuntime("node"), { kind: "node" });
  assert.deepEqual(classifyRuntime("nodejs"), { kind: "node" });
  assert.deepEqual(classifyRuntime("npx"), { kind: "node" });
  assert.deepEqual(classifyRuntime("C:\\Program Files\\nodejs\\node.exe"), { kind: "node" });
  assert.deepEqual(classifyRuntime("./server.mjs"), { kind: "node" });
  assert.deepEqual(classifyRuntime("dist/index.cjs"), { kind: "node" });
  assert.equal(classifyRuntime("python").kind, "unsupported-runtime");
  assert.equal(classifyRuntime("python3").kind, "unsupported-runtime");
  assert.equal(classifyRuntime("uvx").kind, "unsupported-runtime");
  assert.equal(classifyRuntime("go").kind, "unsupported-runtime");
  assert.equal(classifyRuntime("/opt/bin/thing").kind, "unsupported-binary");
  assert.equal(classifyRuntime("./server.py").kind, "unsupported-binary");
  assert.equal(classifyRuntime("mcp-server").kind, "unrecognised");
});

test("describeSource never looks like a path a reader could open", () => {
  assert.equal(
    describeSource({ kind: "command", command: "node", args: ["/target/x.js"] }),
    "<live node /target/x.js>"
  );
  assert.equal(
    describeSource({ kind: "url", url: "http://localhost:9/sse" }),
    "<live http://localhost:9/sse>"
  );
});

/**
 * Type-level half of the lock contract, mirroring sandbox.test.ts's. Never
 * called; it exists so `tsc` fails the build if enumerateFromCommand() ever
 * stops requiring a ScanLock. Starting a container and rewriting host-global
 * netfilter chains without the lock is what the startup sweep would then
 * mistake for an orphan.
 */
export function _enumerateRequiresALockAtCompileTime(): void {
  const plan = { mountDir: "/x", programPath: "/x/i.js", command: "node", args: [] };
  // @ts-expect-error - enumerateFromCommand() must not be callable without a ScanLock
  const withoutLock = (): Promise<EnumerationResult> => enumerateFromCommand(plan);
  // @ts-expect-error - and not with something that merely looks lock-shaped
  const withFake = (): Promise<EnumerationResult> => enumerateFromCommand({ held: true }, plan);
  void withoutLock;
  void withFake;
}

test("enumerateFromCommand refuses a lock that has already been released", async () => {
  const dir = await mkdtemp(join(tmpdir(), "palar-enum-lock-"));
  try {
    const lock = await ScanLock.acquire({ stateDir: dir, probeProcess: aliveProbe });
    await lock.release();

    // Must throw before Docker is touched at all: a released lock is
    // exactly as unsafe to start a container under as no lock.
    await assert.rejects(
      () =>
        enumerateFromCommand(lock, {
          mountDir: dir,
          programPath: join(dir, "index.js"),
          command: "node",
          args: ["/target/index.js"],
        }),
      /requires the live-scan lock to still be held/
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a Windows-style plan still emits POSIX container paths", async () => {
  const root = await projectFixture();
  try {
    const plan = planContainerCommand(
      "node",
      [join("node_modules", "@scope", "server", "dist", "index.js")],
      root
    );
    // Whatever the host separator is, the container is Linux. On Windows
    // `join()` above produces backslashes, and a backslash reaching the
    // container is a path the target simply cannot open.
    assert.ok(
      !plan.args[0]!.includes("\\"),
      `container path leaked a host separator (${sep}): ${plan.args[0]}`
    );
    assert.equal(plan.args[0], "/target/node_modules/@scope/server/dist/index.js");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

/**
 * Passthrough. These pin the contract toToolDefinitions()'s docstring
 * states — every modelled field survives when present, and is omitted when
 * absent — because the failure it guards against is silent and asymmetric:
 * a field the JSON-file path can see and the live path cannot makes the two
 * commands disagree about one server with no way to tell which is wrong.
 */
test("a live tool's title, annotations, and outputSchema all survive normalization", () => {
  const [tool] = toToolDefinitions([
    {
      name: "probe_host",
      title: "Check host reachability",
      description: "Checks whether a host is reachable.",
      annotations: { readOnlyHint: true, openWorldHint: false },
      inputSchema: { type: "object", properties: { hostname: { type: "string" } } },
      outputSchema: { type: "object", properties: { reachable: { type: "boolean" } } },
    },
  ]);

  assert.equal(tool!.title, "Check host reachability");
  assert.deepEqual(tool!.annotations, { readOnlyHint: true, openWorldHint: false });
  assert.deepEqual(tool!.outputSchema, {
    type: "object",
    properties: { reachable: { type: "boolean" } },
  });
});

test("the annotations.title position survives too", () => {
  const [tool] = toToolDefinitions([
    { name: "t", annotations: { title: "Label", openWorldHint: false } },
  ]);
  assert.equal(tool!.annotations?.title, "Label");
});

test("an unmodelled annotation is carried rather than stripped", () => {
  // A hint palar has no model for is still the server's own claim; editing
  // it out would mean palar reporting on its own paraphrase.
  const [tool] = toToolDefinitions([
    { name: "t", annotations: { readOnlyHint: true, vendorHint: "x" } },
  ]);
  assert.equal((tool!.annotations as Record<string, unknown>)["vendorHint"], "x");
});

test("absent optional fields are omitted, not filled in", () => {
  const [tool] = toToolDefinitions([{ name: "t" }]);
  assert.ok(!("title" in tool!), "title should be absent, not undefined-valued");
  assert.ok(!("annotations" in tool!), "annotations should be absent");
  assert.ok(!("outputSchema" in tool!), "outputSchema should be absent");
  assert.ok(!("description" in tool!), "description should be absent");
});

test("non-object annotations are dropped rather than carried as garbage", () => {
  const [tool] = toToolDefinitions([{ name: "t", annotations: "read-only" }]);
  assert.ok(!("annotations" in tool!));
});


// ---------------------------------------------------------------------------
// findPlatformMismatches
//
// The whole risk in this check is over-firing. A miss leaves today's
// behaviour (the target's own error); a false positive refuses to scan a
// server that would have worked, and tells the user to "fix" an install that
// is already correct. Every negative case below is therefore load-bearing,
// and there are deliberately more of them than positive ones.
// ---------------------------------------------------------------------------

/** Writes a package into `<root>/node_modules/<name>` with the given manifest. */
async function installed(
  root: string,
  name: string,
  manifest: Record<string, unknown>
): Promise<void> {
  const dir = join(root, "node_modules", ...name.split("/"));
  await mkdir(dir, { recursive: true });
  await writeFile(
    join(dir, "package.json"),
    JSON.stringify({ name, version: "1.0.0", ...manifest })
  );
}

async function targetRoot(): Promise<string> {
  return mkdtemp(join(tmpdir(), "palar-platform-"));
}

// The sandbox container runs linux on the host's own architecture (see
// SANDBOX_CPU). These tests must assert that, not a hardcoded x64, or they
// would pass on CI and fail on an Apple Silicon laptop.
const NATIVE = process.arch;
const FOREIGN = process.arch === "arm64" ? "x64" : "arm64";

test("a Windows-only package with no Linux sibling is reported", async () => {
  const root = await targetRoot();
  try {
    await installed(root, "@esbuild/win32-x64", { os: ["win32"], cpu: [NATIVE] });
    const found = findPlatformMismatches(root);
    assert.equal(found.length, 1);
    assert.equal(found[0]!.name, "@esbuild/win32-x64");
    assert.deepEqual(found[0]!.os, ["win32"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a package installed FOR linux-x64 stays silent", async () => {
  // The documented `--os=linux --cpu=x64` workaround. This install is
  // correct and the target will start; firing here would be the single
  // worst outcome for this check.
  const root = await targetRoot();
  try {
    await installed(root, "@esbuild/linux-native", { os: ["linux"], cpu: [NATIVE] });
    assert.deepEqual(findPlatformMismatches(root), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("both platforms installed side by side stays silent", async () => {
  // yarn's supportedArchitectures, or `npm install --force`. The binary the
  // container needs is present, so the target runs.
  const root = await targetRoot();
  try {
    await installed(root, "@esbuild/win32-x64", { os: ["win32"], cpu: [NATIVE] });
    await installed(root, "@esbuild/linux-native", { os: ["linux"], cpu: [NATIVE] });
    assert.deepEqual(findPlatformMismatches(root), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("one broken scope is reported even when another scope is fine", async () => {
  const root = await targetRoot();
  try {
    await installed(root, "@esbuild/linux-native", { os: ["linux"], cpu: [NATIVE] });
    await installed(root, "@rollup/rollup-win32-x64-msvc", {
      os: ["win32"],
      cpu: [NATIVE],
    });
    const found = findPlatformMismatches(root);
    assert.equal(found.length, 1);
    assert.equal(found[0]!.name, "@rollup/rollup-win32-x64-msvc");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("packages declaring no os/cpu are never reported", async () => {
  const root = await targetRoot();
  try {
    await installed(root, "zod", {});
    await installed(root, "@modelcontextprotocol/sdk", {});
    assert.deepEqual(findPlatformMismatches(root), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("npm's negation and 'any' forms are honoured, not guessed at", async () => {
  const root = await targetRoot();
  try {
    // `!win32` permits linux. `any` permits everything. Treating either as
    // an allowlist would refuse a target that runs perfectly well.
    await installed(root, "not-windows", { os: ["!win32"] });
    await installed(root, "anywhere", { os: ["any"], cpu: ["any"] });
    await installed(root, "string-form", { os: "linux" });
    assert.deepEqual(findPlatformMismatches(root), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a denied linux, or a foreign cpu, is reported", async () => {
  const root = await targetRoot();
  try {
    await installed(root, "no-linux", { os: ["!linux"] });
    await installed(root, "foreign-cpu-only", { cpu: [FOREIGN] });
    const names = findPlatformMismatches(root)
      .map((m) => m.name)
      .sort();
    assert.deepEqual(names, ["foreign-cpu-only", "no-linux"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("a missing or unreadable node_modules is not a mismatch", async () => {
  const root = await targetRoot();
  try {
    assert.deepEqual(findPlatformMismatches(root), []);
    await mkdir(join(root, "node_modules", "broken"), { recursive: true });
    await writeFile(join(root, "node_modules", "broken", "package.json"), "{ not json");
    assert.deepEqual(findPlatformMismatches(root), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("an unscoped package is judged only against itself", async () => {
  // Grouping is by scope; two unrelated unscoped packages must not cover
  // for each other the way two members of one scope do.
  const root = await targetRoot();
  try {
    await installed(root, "linux-thing", { os: ["linux"] });
    await installed(root, "windows-thing", { os: ["win32"] });
    const found = findPlatformMismatches(root);
    assert.equal(found.length, 1);
    assert.equal(found[0]!.name, "windows-thing");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
