/**
 * Tool enumeration from a running server, for `palar scan --from-url` and
 * `palar scan --from-command`.
 *
 * The question this answers is narrow and worth stating precisely: *where
 * do the tool definitions come from?* Ordinary `palar scan` reads them from
 * JSON files on disk, which means it analyses whatever a human wrote down.
 * These two flags instead take them from the server itself over a real MCP
 * connection — `listTools()`, once — and hand the result to the exact same
 * rule set. Same rules, same score, different source of truth.
 *
 * This is enumeration, not probing. No tool is ever called, no payload is
 * ever built, and no oracle is started. That is not a limitation to work
 * around later; it is what makes `--from-url` safe to point at a server
 * you do not own, and it is why the `--from-command` sandbox installs its
 * firewall with no ACCEPT hole at all (nothing needs to call back). If you
 * want a tool actually exercised, that is `palar live`, which is a
 * different command with a different consent gate.
 *
 * The two paths differ sharply in what they do to the host, which is why
 * they are separate flags rather than one flag with a heuristic:
 *
 *   - `--from-url` connects to something already running somewhere else.
 *     It spawns nothing, creates no container, and takes no lock. Its
 *     entire footprint is one outbound HTTP connection.
 *   - `--from-command` starts a process. It therefore runs inside the same
 *     Docker sandbox `palar live` uses, and takes the same host-wide
 *     lock — unconditionally, with no flag to turn either off. See
 *     planContainerCommand() below for the sharp edge in that: the sandbox
 *     provides a Node runtime and a read-only mount of your disk, and
 *     nothing else.
 */
import { existsSync, statSync } from "node:fs";
import { isAbsolute, parse as parsePath, relative, resolve, sep } from "node:path";
import type { MCPServerConfig, MCPToolDefinition } from "../core/types.js";
import { connectLive, type LiveConnection } from "./connector.js";
import { TargetSandbox } from "./sandbox.js";
import type { ScanLock } from "./lock.js";

/** Where a set of tool definitions came from, for reports and JSON output. */
export type EnumerationSource =
  | { kind: "url"; url: string }
  | { kind: "command"; command: string; args: string[] };

/**
 * Outcome of one enumeration attempt.
 *
 * A discriminated union rather than "an array that might be empty", because
 * the three cases are not degrees of the same result — they are different
 * events that must not be scored the same way:
 *
 *   - `enumerated` — the server answered with at least one tool. There is
 *     something to analyse, so a score is meaningful.
 *   - `no-tools`   — the connection and handshake succeeded and the server
 *     said, truthfully, that it exposes nothing. Nothing was examined, so
 *     no score is emitted. A 100/A here would be a claim about a server
 *     palar never looked at.
 *   - `never-reached` — palar never got a tool list at all: the command
 *     could not be planned, the container never started, the handshake
 *     timed out, the URL refused the connection. This says nothing
 *     whatsoever about the target's security posture.
 *
 * Returning an empty array for the last two and letting the caller guess
 * is exactly how a scan of nothing turns into a clean bill of health. The
 * caller cannot accidentally treat these alike, because the tools field
 * only exists on the one case that has tools.
 */
export type EnumerationResult =
  | {
      outcome: "enumerated";
      source: EnumerationSource;
      tools: MCPToolDefinition[];
      durationMs: number;
    }
  | { outcome: "no-tools"; source: EnumerationSource; durationMs: number }
  | {
      outcome: "never-reached";
      source: EnumerationSource;
      error: string;
      durationMs: number;
    };

export interface EnumerateOptions {
  /** Milliseconds to wait for the connect/handshake. Defaults to connector.ts's own default. */
  connectTimeoutMs?: number;
  /**
   * Hard ceiling for the whole enumeration, default 180000ms. Races
   * everything, connect included — so it has to stay above the connect
   * timeout or it silently preempts it. Enumeration itself is one
   * `listTools()`, so this budget is almost entirely the connect: see
   * connector.ts for the per-target measurements behind the 90s default
   * it must clear.
   */
  overallTimeoutMs?: number;
  /**
   * Environment variables to set inside the container, `--from-command`
   * only. Exactly these and nothing else: the same contract env.ts states
   * for a manifest's `"env"` field, and for the same reason — palar must
   * never hand a target ambient host credentials just because they were in
   * scope in palar's own process. These come from the command line, so
   * they are always something the user typed on purpose.
   */
  env?: Record<string, string>;
}

/** Thrown when a `--from-command` argv cannot be turned into a runnable container command. */
export class EnumerationPlanError extends Error {}

/** How a `--from-command` argv is rewritten to run inside the sandbox container. */
export interface ContainerCommandPlan {
  /** Host directory bind-mounted read-only at /target. */
  mountDir: string;
  /** The host path of the program file the plan is anchored on. */
  programPath: string;
  /** argv[0] as written inside the container. */
  command: string;
  /** Remaining argv as written inside the container. */
  args: string[];
}

/**
 * A short, human-readable label for where definitions came from. Used as
 * the `file` field on findings, so it deliberately does not look like a
 * path — a reader scanning a report should never mistake it for something
 * they can open.
 */
export function describeSource(source: EnumerationSource): string {
  return source.kind === "url"
    ? `<live ${source.url}>`
    : `<live ${[source.command, ...source.args].join(" ")}>`;
}

/**
 * Turns a host argv into one that runs inside the sandbox container.
 *
 * The container is not this machine. It gets a Node runtime, an empty
 * network, no DNS, and one read-only bind mount — so a host path in the
 * argv is meaningless inside it unless that path is inside the mount and
 * rewritten to its container-side equivalent. That is all this function
 * does, and the honest shape of what it can and cannot support falls
 * directly out of it:
 *
 *   - It anchors on the first argv token that is an existing *file* on
 *     this disk. That is the program. `node ./dist/index.js` anchors on
 *     `./dist/index.js`; `node node_modules/@scope/pkg/dist/index.js`
 *     anchors on that.
 *   - **If no token is an existing file, there is nothing to run and this
 *     throws.** `npx -y @scope/some-server` and `uvx some-server` land
 *     here: they name a package to be *fetched*, and the sandbox has no
 *     network to fetch it with. Failing loudly at plan time is the point —
 *     the alternative is a container that starts, fails to resolve a
 *     registry, and reports as a connect timeout, which reads like a
 *     broken target rather than an unsupported invocation.
 *   - The mount root is derived from the program path, not from the
 *     current directory, because Node resolves `node_modules` by walking
 *     *up* from the script. Mounting only the script's own directory
 *     produces a container where the program exists but none of its
 *     dependencies do. So: if the path runs through a `node_modules`
 *     segment, the mount is the parent of the outermost one (a package
 *     installed at `<root>/node_modules/@scope/pkg/...` needs all of
 *     `<root>` visible, since its own dependencies are siblings, not
 *     children). Otherwise it is the nearest ancestor that looks like a
 *     project root — one containing `package.json` or `node_modules`.
 *   - Every other token is rewritten only if it resolves to a path inside
 *     the mount; anything else passes through untouched. So `--headless`
 *     stays `--headless`, and a container-side path like `/tmp` stays
 *     `/tmp` and means the container's `/tmp`, not this host's.
 *
 * What this does not do is make a non-Node program work. The runtime image
 * ships Node and curl; a Python or Go or compiled-binary server will be
 * planned successfully and then fail to execute inside the container. That
 * limitation belongs to the image, is named in --help and the README, and
 * is not papered over here.
 */
/**
 * The first token in an argv that names a file existing on this disk, or
 * `undefined` when none does.
 *
 * Shared by the two places that start a target inside the sandbox, because
 * the failure it prevents is identical in both and only one of them used to
 * catch it. The container image provides Node and nothing else, and
 * `node:20-slim`'s entrypoint runs `node "$@"` for any argv[0] that is not
 * a system command — so a target declared as `python -m mcp_server_fetch`
 * does not fail with "python: not found". It reaches Node as a *script
 * path* and dies with `Cannot find module '/target/python'`, which reads
 * like a broken target rather than an unsupported invocation. There is no
 * point starting a container to learn that.
 *
 * Existence is the whole test, deliberately. Whether the file is a
 * *runnable* Node program is not knowable from the host, and pretending
 * otherwise would trade a precise check for a guess.
 */
export function findProgramToken(tokens: string[], cwd: string): string | undefined {
  const isExistingFile = (token: string): boolean => {
    // Bare `-`-prefixed flags are never paths; skipping them avoids an
    // absurd-but-possible collision with a file of the same name sitting
    // in the working directory.
    if (token.startsWith("-")) return false;
    try {
      return statSync(resolve(cwd, token)).isFile();
    } catch {
      return false;
    }
  };
  return tokens.find(isExistingFile);
}

export function planContainerCommand(
  command: string,
  args: string[],
  cwd: string = process.cwd()
): ContainerCommandPlan {
  const tokens = [command, ...args];

  const programToken = findProgramToken(tokens, cwd);
  if (programToken === undefined) {
    throw new EnumerationPlanError(
      `--from-command could not find a program to run: none of \`${tokens.join(" ")}\` names a ` +
        "file that exists on this disk. This flag runs a server you already have installed " +
        "locally — the sandbox has no network and no package manager, so an invocation that " +
        "asks a registry for the server (npx, uvx, pipx) cannot work here. Install it first " +
        "and point --from-command at the installed entry point, e.g. " +
        "`--from-command node node_modules/@scope/server/dist/index.js`."
    );
  }

  const programPath = resolve(cwd, programToken);
  const mountDir = deriveMountDir(programPath);

  const toContainerPath = (token: string): string => {
    if (token.startsWith("-")) return token;
    const abs = resolve(cwd, token);
    if (!existsSync(abs)) return token;
    const rel = relative(mountDir, abs);
    // "" means the token *is* the mount root; a leading ".." or an absolute
    // result means it is outside it. Neither is rewritable — outside the
    // mount there is nothing in the container to point at.
    if (rel === "" || rel.startsWith("..") || isAbsolute(rel)) return token;
    return `/target/${rel.split(sep).join("/")}`;
  };

  const planned = tokens.map(toContainerPath);
  return {
    mountDir,
    programPath,
    command: planned[0]!,
    args: planned.slice(1),
  };
}

/**
 * The mount root for a given program path — see planContainerCommand()'s
 * docstring for why this is not simply the script's directory.
 */
function deriveMountDir(programPath: string): string {
  const { root } = parsePath(programPath);
  const segments = programPath.slice(root.length).split(sep);

  // Outermost node_modules wins. A dependency of a dependency lives at
  // <root>/node_modules/a/node_modules/b, and mounting the *inner* parent
  // would hide everything `a` itself needs.
  const nmIndex = segments.indexOf("node_modules");
  if (nmIndex > 0) {
    return root + segments.slice(0, nmIndex).join(sep);
  }

  // No node_modules in the path: walk up looking for something that looks
  // like a project root. Stops at the filesystem root rather than mounting
  // it — handing a container the whole disk, even read-only, is not a
  // reasonable default for "I could not work out what to mount".
  let dir = resolve(programPath, "..");
  for (;;) {
    if (existsSync(resolve(dir, "package.json")) || existsSync(resolve(dir, "node_modules"))) {
      return dir;
    }
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }

  // Nothing project-shaped anywhere above it: a standalone script. Its own
  // directory is the most that can be justified.
  const own = resolve(programPath, "..");
  if (own === root) {
    throw new EnumerationPlanError(
      `--from-command refuses to bind-mount the filesystem root for ${programPath}. Move the ` +
        "server into a directory of its own and point --from-command at it there."
    );
  }
  return own;
}

/** Normalizes the SDK's tool list into the same shape the static rules already consume. */
function toToolDefinitions(listed: unknown[]): MCPToolDefinition[] {
  const definitions: MCPToolDefinition[] = [];
  for (const entry of listed) {
    if (typeof entry !== "object" || entry === null) continue;
    const tool = entry as { name?: unknown; description?: unknown; inputSchema?: unknown };
    if (typeof tool.name !== "string") continue;
    definitions.push({
      name: tool.name,
      ...(typeof tool.description === "string" ? { description: tool.description } : {}),
      // Passed through as-is rather than reshaped. Whatever the server
      // actually serves is what the rules should judge; normalizing it
      // here would mean palar rates its own interpretation of the schema
      // instead of the schema.
      ...(typeof tool.inputSchema === "object" && tool.inputSchema !== null
        ? { inputSchema: tool.inputSchema as MCPToolDefinition["inputSchema"] }
        : {}),
    });
  }
  return definitions;
}

/**
 * Shared tail of both paths: list the tools on an established connection
 * and classify the outcome. Never throws — a failure here is a
 * `never-reached`, since without a tool list nothing was examined.
 */
async function listAndClassify(
  connection: LiveConnection,
  source: EnumerationSource,
  start: number,
  timeoutMs: number
): Promise<EnumerationResult> {
  // Bounded by the caller's own ceiling rather than the SDK's hidden 60s
  // default, for the same reason connectWithTimeout() exists: --timeout-ms
  // must mean what it says.
  const listed = await connection.client.listTools(undefined, { timeout: timeoutMs });
  const tools = toToolDefinitions(listed.tools as unknown[]);
  const durationMs = Date.now() - start;
  return tools.length === 0
    ? { outcome: "no-tools", source, durationMs }
    : { outcome: "enumerated", source, tools, durationMs };
}

function withDeadline<T>(work: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} exceeded ${ms}ms`)), ms);
  });
  return Promise.race([work, deadline]).finally(() => clearTimeout(timer));
}

/**
 * Enumerates a server that is already running somewhere else, over SSE.
 *
 * Spawns nothing and takes no lock, because there is nothing local to
 * contain: the process is somebody else's and was running before palar
 * showed up. The only thing that leaves this machine is an MCP handshake
 * and a `tools/list` request.
 *
 * SSE specifically, not "any MCP URL": that is the transport connector.ts
 * implements. A streamable-HTTP endpoint will fail to connect and be
 * reported as never-reached.
 */
export async function enumerateFromUrl(
  url: string,
  opts: EnumerateOptions = {}
): Promise<EnumerationResult> {
  const source: EnumerationSource = { kind: "url", url };
  const start = Date.now();
  const overallTimeoutMs = opts.overallTimeoutMs ?? 180_000;
  const server: MCPServerConfig = { name: url, transport: "sse", url };

  let connection: LiveConnection | null = null;
  try {
    return await withDeadline(
      (async () => {
        connection = await connectLive(server, { connectTimeoutMs: opts.connectTimeoutMs });
        return listAndClassify(connection, source, start, overallTimeoutMs);
      })(),
      overallTimeoutMs,
      `enumeration of ${url}`
    );
  } catch (err) {
    return {
      outcome: "never-reached",
      source,
      error: (err as Error).message,
      durationMs: Date.now() - start,
    };
  } finally {
    if (connection) {
      try {
        await (connection as LiveConnection).close();
      } catch {
        // Nothing local was started; a failed close leaks no host state.
      }
    }
  }
}

/**
 * Enumerates a server by starting it — inside the sandbox, always.
 *
 * The `lock` parameter is required for the same reason
 * sweepOrphanedSandboxState()'s is: this call creates a container, a
 * network, and host-global netfilter rules, and the startup sweep that
 * reclaims orphaned versions of exactly those objects cannot tell a
 * crashed run's leftovers from a concurrent run's live state. Demanding a
 * ScanLock makes "the caller serialized this" a compile error to omit
 * rather than a comment to miss, and assertHeld() covers the case the type
 * system cannot see — a lock legitimately obtained and since released.
 *
 * The firewall is installed with `null`: enumeration calls no tool, so
 * nothing needs to call back, so the container gets no permitted egress
 * whatsoever. That is a tighter posture than `palar live`'s, and it is
 * available precisely because this path does less.
 */
export async function enumerateFromCommand(
  lock: ScanLock,
  plan: ContainerCommandPlan,
  opts: EnumerateOptions = {}
): Promise<EnumerationResult> {
  lock.assertHeld("enumerateFromCommand()");

  const source: EnumerationSource = { kind: "command", command: plan.command, args: plan.args };
  const start = Date.now();
  const overallTimeoutMs = opts.overallTimeoutMs ?? 180_000;
  const server: MCPServerConfig = {
    name: describeSource(source),
    transport: "stdio",
    command: plan.command,
    args: plan.args,
    // Reaches the container as `-e KEY=VAL` via sandbox.ts's buildCleanEnv,
    // the identical path a manifest's own "env" takes.
    ...(opts.env ? { env: opts.env } : {}),
  };

  const holder: { connection: LiveConnection | null; sandbox: TargetSandbox | null } = {
    connection: null,
    sandbox: null,
  };

  try {
    return await withDeadline(
      (async () => {
        const sandbox = await TargetSandbox.create();
        holder.sandbox = sandbox;
        await sandbox.installFirewall(null);
        const connection = await connectLive(server, {
          targetDir: plan.mountDir,
          connectTimeoutMs: opts.connectTimeoutMs,
          sandbox,
        });
        holder.connection = connection;
        return listAndClassify(connection, source, start, overallTimeoutMs);
      })(),
      overallTimeoutMs,
      `enumeration of ${describeSource(source)}`
    );
  } catch (err) {
    return {
      outcome: "never-reached",
      source,
      error: (err as Error).message,
      durationMs: Date.now() - start,
    };
  } finally {
    // Same unconditional-teardown rigor as liveScan.ts: success, failure
    // and timeout all reach here, and the sandbox teardown runs again
    // defensively in case connectLive() threw before a connection existed.
    if (holder.connection) {
      try {
        await holder.connection.close();
      } catch {
        // teardown() below is the real backstop for container state.
      }
    }
    if (holder.sandbox) await holder.sandbox.teardown();
  }
}
