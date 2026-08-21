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
  describeSource,
  enumerateFromCommand,
  EnumerationPlanError,
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

test("refuses a registry-fetch invocation instead of failing later as a timeout", () => {
  // The named limitation, enforced in code rather than only in --help:
  // npx/uvx name a package to fetch, and the sandbox has no network.
  for (const argv of [
    ["npx", "-y", "@scope/some-server"],
    ["uvx", "mcp-server-fetch"],
    ["python", "-m", "mcp_server_fetch"],
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
