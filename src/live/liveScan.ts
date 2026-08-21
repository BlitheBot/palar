/**
 * Orchestrates one live scan: connect to the real target, list its actual
 * tools, probe the ones that look injectable, and check description
 * poisoning against the live (not just static-file) content.
 *
 * Safety posture for stdio targets (see sandbox.ts for exactly what is and
 * isn't covered):
 *   - the target's declared command runs inside an ephemeral, network-
 *     restricted Docker container, mounted read-only, with dropped
 *     capabilities and resource limits — not directly on this host
 *   - the container's only permitted egress is to this scan's own oracle
 *     callback listener; everything else is rejected at the firewall,
 *     both forwarded traffic (DOCKER-USER) and host-destined traffic
 *     (INPUT) — the latter is what services listening on the host itself
 *     would otherwise be reachable through
 *   - the container has no working DNS resolver at all, so it cannot
 *     resolve arbitrary hostnames; the oracle callback works regardless
 *     because host.docker.internal is pinned in the container's /etc/hosts
 *   - the whole scan is bounded by a hard overall timeout, and the
 *     container/network/firewall rules are torn down unconditionally in
 *     `finally`, success, failure, or timeout; anything an earlier crashed
 *     run orphaned is reclaimed by the CLI's startup sweep
 * NOT covered: this is container isolation (Docker + iptables), not a VM
 * or gVisor — a kernel-level container escape isn't mitigated. See
 * README.md's "Live scanning" section for the full list of what's still
 * out of scope (oracle rate-limiting, a shared *remote* daemon driven from
 * two machines, etc.). Concurrent scans on this host are no longer a race:
 * the CLI serializes them behind an exclusive lock (live/lock.ts) taken
 * before any sandbox state exists and held for the whole run.
 * SSE targets have no local process to sandbox and are unaffected —
 * this module's safety posture for them is unchanged: a clean env is moot
 * (nothing is spawned) and only the overall timeout applies.
 */
import { CallbackOracle } from "./oracle.js";
import { resolveProbeStatus, wouldBeRejected } from "./status.js";
import {
  buildBenignArguments,
  controlGateDecision,
  sendControlCall,
} from "./control.js";
import { connectLive, type LiveConnection } from "./connector.js";
import { TargetSandbox } from "./sandbox.js";
import {
  classifyExecutionAdjacentFields,
  detectPoisonedDescription,
  buildCommandInjectionPayload,
  buildSsrfPayload,
  buildProbeArguments,
  benignValueFor,
  type LiveTool,
  type FieldProbeTarget,
} from "./probes.js";
import { findProgramToken } from "./enumerate.js";
import { isConstrained } from "../rules/input-validation.js";
import type { MCPServerConfig, MCPToolDefinition } from "../core/types.js";
import type {
  ControlCall,
  LiveAuditResult,
  LiveProbeResult,
  PoisoningLiveCheck,
  ToolCallCapture,
  ToolDriftEntry,
} from "./types.js";

export interface LiveScanOptions {
  /** Read-only container mount root for stdio targets — the target's own directory, not palar's. */
  targetDir?: string;
  /**
   * How long to wait for the TARGET to answer the MCP handshake, default
   * 90000ms. For a stdio target this clock starts once the container is
   * running — palar's own container start has its own budget below.
   */
  connectTimeoutMs?: number;
  /** How long to wait for palar's own sandbox container to start, default 120000ms. */
  containerStartTimeoutMs?: number;
  /**
   * Called when palar has to build a sandbox image before it can run
   * anything. First run only; it is slow and otherwise silent.
   */
  onImageBuild?: (image: string) => void;
  /** How long to wait for an oracle callback after each probe call, default 4000ms. */
  callbackTimeoutMs?: number;
  /**
   * Ceiling for a single benign control call, default: whatever
   * `callbackTimeoutMs` is.
   *
   * The cost of the control call is not latency — a benign call has no
   * oracle wait, and measured against a local stdio target it is a
   * single-digit-millisecond round trip. The cost is BLOCKING: a tool that
   * launches a browser, or waits out its own long internal HTTP timeout,
   * would otherwise add that whole wait to the scan. Bounding it at the
   * callback timeout keeps a controlled probe costing about what one probe
   * already costs.
   */
  controlTimeoutMs?: number;
  /**
   * Hard ceiling for the scan itself — connect, listTools, and every probe —
   * default 180000ms.
   *
   * Deliberately does NOT cover palar's own setup. Building the sandbox
   * image, creating the network and starting the oracle all happen before
   * this clock starts, because they are palar getting ready rather than the
   * target being slow, and a first run that has to fetch a 300MB base image
   * must not be reported as a target that never answered. Container start
   * is likewise budgeted separately (containerStartTimeoutMs).
   *
   * What it does have to cover: a worst-case 90s handshake plus the probing
   * phase, measured at 48-49s on the two slowest targets in the sample
   * (server-filesystem's 11 probes, desktop-commander's 12). So 90 + 50
   * with headroom.
   */
  overallTimeoutMs?: number;
  /**
   * Oracle bind host — only meaningful for SSE targets. For stdio targets
   * the oracle instead binds to whatever sandbox.ts's TargetSandbox decides
   * is actually reachable/bindable on this Docker backend (host loopback
   * on Docker Desktop, the sandbox network's gateway address on native
   * Linux Engine — see sandbox.ts's `oracleBindHost`); this option is
   * ignored in that case.
   */
  oracleHost?: string;
}

function captureToolResult(result: unknown): ToolCallCapture {
  const r = result as { isError?: boolean; content?: { type: string; text?: string }[] };
  const texts = Array.isArray(r.content)
    ? r.content
        .filter((c) => c.type === "text" && typeof c.text === "string")
        .map((c) => c.text as string)
    : [];
  const joined = texts.join("\n");
  return {
    isError: r.isError,
    textPreview: joined.length > 500 ? `${joined.slice(0, 500)}…` : joined,
  };
}

async function callToolSafely(
  connection: LiveConnection,
  toolName: string,
  args: Record<string, unknown>
): Promise<ToolCallCapture | { error: string }> {
  try {
    const result = await connection.client.callTool({ name: toolName, arguments: args });
    return captureToolResult(result);
  } catch (err) {
    return { error: (err as Error).message };
  }
}

async function runOneProbe(
  connection: LiveConnection,
  oracle: CallbackOracle,
  tool: LiveTool,
  target: FieldProbeTarget,
  callbackTimeoutMs: number
): Promise<LiveProbeResult> {
  const nonce = oracle.newNonce(`${tool.name}-${target.fieldPath}`);
  const callbackUrl = oracle.callbackUrl(nonce);
  const payload =
    target.kind === "ssrf"
      ? buildSsrfPayload(callbackUrl)
      : buildCommandInjectionPayload("127.0.0.1", callbackUrl);
  // The plan carries the arguments AND whatever the target's declared
  // schema demands of them that palar could not deliver. The probe is sent
  // either way — a server that does not enforce its own declaration will
  // run it, and a callback outranks everything — but the issues travel
  // with the result so a failure is not misread as the target refusing the
  // payload. See status.ts's "not-tested".
  const { args, issues } = buildProbeArguments(tool, target, payload);

  const toolCall = await callToolSafely(connection, tool.name, args);
  const callback = await oracle.waitForCallback(nonce, callbackTimeoutMs);

  return {
    toolName: tool.name,
    fieldPath: target.fieldPath,
    kind: target.kind,
    reason: target.reason,
    payload,
    nonce,
    argumentIssues: issues,
    // Provisional. A probe that would otherwise be `rejected` gets a
    // benign control call afterwards, which can move it to
    // `inconclusive` — see finalizeToolProbes() below. Every other status
    // is already final here: a control call is never sent for one, and
    // resolveProbeStatus() would ignore it if it were.
    status: resolveProbeStatus(callback, toolCall, issues, null),
    callback,
    callbackTimeoutMs,
    toolCall,
    control: null,
  };
}

/**
 * The benign sentence used wherever a schema genuinely accepts free-form
 * prose. Shared by the control call and the poisoning check so the two are
 * literally the same call, which is what lets a poisoning check's result
 * stand in as a control observation at zero extra cost.
 */
const BENIGN_SENTENCE =
  "This is a benign sentence sent by a security scanner. It has two sentences.";

/**
 * Resolves the control call for one tool, at most once per scan, and
 * applies it to that tool's probes.
 *
 * ## Why the control comes AFTER the payload
 *
 * Sending it first would mean mutating the target before the payload
 * lands. A benign call that consumes a resource, trips a rate limiter, or
 * advances a state machine changes what the payload then hits — and a
 * probe corrupted that way can land in `unconfirmed`, which reads as "the
 * target accepted the payload and said nothing". That is a false-clean,
 * the one direction this pass refuses to fail in.
 *
 * Control-after has its own failure mode — a payload that wedged the
 * handler makes the control error, and the probe reads `inconclusive` when
 * the tool was working fine until palar broke it. That is the
 * non-reassuring direction, so it is the better trade. It is recorded in
 * status.ts's honest-limit list as cause (6) rather than hidden.
 *
 * ## Why it is conditional and memoized
 *
 * Only a probe that would otherwise resolve to `rejected` has an error a
 * control could explain. A confirmed probe is settled by its callback, a
 * not-tested one is already explained by palar's own arguments, and an
 * unconfirmed one has no error at all. So the cost is not one call per
 * probe: it is one call per TOOL that produced at least one errored probe.
 * classifyExecutionAdjacentFields() can return several targets on the same
 * tool, and one answer to "does this tool run here" serves all of them.
 *
 * `seed` lets a poisoning check that already made the identical benign
 * call stand in, so those tools cost nothing at all.
 */
async function finalizeToolProbes(
  connection: LiveConnection,
  tool: LiveTool,
  probes: LiveProbeResult[],
  transportKind: "stdio" | "sse",
  controlTimeoutMs: number,
  seed: ControlCall | null
): Promise<void> {
  const needsControl = probes.filter((p) =>
    wouldBeRejected(p.callback, p.toolCall, p.argumentIssues)
  );
  if (needsControl.length === 0) return;

  let control = seed;
  if (!control) {
    const gate = controlGateDecision(tool, transportKind);
    control = gate.allowed
      ? await sendControlCall(
          connection,
          tool.name,
          buildBenignArguments(tool, BENIGN_SENTENCE, benignValueFor),
          controlTimeoutMs,
          captureToolResult
        )
      : { attempted: false, reason: gate.reason };
  }

  for (const probe of needsControl) {
    probe.control = control;
    probe.status = resolveProbeStatus(
      probe.callback,
      probe.toolCall,
      probe.argumentIssues,
      control
    );
  }
}

/**
 * The live description-poisoning check, and — when it makes its call — a
 * free control observation for that tool.
 *
 * ## Why this path is gated now
 *
 * This check has always sent a benign, schema-valid, payload-free call to
 * any tool carrying a zero-width code point in its description, and it did
 * so with no side-effect gate of any kind. It predates the gate. A gate on
 * the control call with this path left open would not be a gate, so the
 * same rule applies here: see control.ts's controlGateDecision().
 *
 * The consequence is a real, accepted loss of coverage. A poisoned
 * `delete_everything` no longer gets its behaviour sampled, and the check
 * reports the poisoning plus the reason the call was withheld. That is the
 * correct trade — the poisoning finding stands on the description alone,
 * which is where the evidence for it was in the first place.
 *
 * ## Why its result doubles as a control
 *
 * The arguments it builds are now literally the same ones the control call
 * builds (buildBenignArguments), so when this fires, the tool has already
 * answered the exact question a control call asks. Returning it lets the
 * probe loop skip a redundant call entirely.
 */
async function runPoisoningCheck(
  connection: LiveConnection,
  tool: LiveTool,
  staticTools: Map<string, MCPToolDefinition>,
  transportKind: "stdio" | "sse",
  controlTimeoutMs: number
): Promise<{ check: PoisoningLiveCheck; control: ControlCall | null } | null> {
  const hit = detectPoisonedDescription(tool);
  if (!hit) return null;

  const staticDef = staticTools.get(tool.name);
  const liveDescriptionMatchesStatic =
    staticDef && typeof staticDef.description === "string"
      ? staticDef.description === tool.description
      : null;

  const gate = controlGateDecision(tool, transportKind);
  if (!gate.allowed) {
    return {
      check: {
        toolName: tool.name,
        codePoints: hit.codePoints,
        liveDescriptionMatchesStatic,
        toolCall: null,
        withheldReason: gate.reason,
      },
      control: { attempted: false, reason: gate.reason },
    };
  }

  // Required properties only, and a benign sentence only where the schema
  // actually accepts a free-form string — same reasoning as
  // buildProbeArguments. Blanket-filling every property with a sentence
  // bounced this call on any enum'd or non-string field, which made the
  // captured "direct tool call response" an argument-validation error
  // rather than the tool's own behavior.
  const control = await sendControlCall(
    connection,
    tool.name,
    buildBenignArguments(tool, BENIGN_SENTENCE, benignValueFor),
    controlTimeoutMs,
    captureToolResult
  );

  return {
    check: {
      toolName: tool.name,
      codePoints: hit.codePoints,
      liveDescriptionMatchesStatic,
      toolCall: control.attempted ? control.toolCall : null,
      withheldReason: null,
    },
    control,
  };
}

export async function runLiveScan(
  server: MCPServerConfig,
  staticTools: { file: string; definition: MCPToolDefinition }[],
  opts: LiveScanOptions = {}
): Promise<LiveAuditResult> {
  const start = Date.now();
  const overallTimeoutMs = opts.overallTimeoutMs ?? 180_000;
  const callbackTimeoutMs = opts.callbackTimeoutMs ?? 4_000;
  // Defaults to the callback timeout rather than to a number of its own:
  // the bound that matters is "a control must not cost more than a probe
  // already does", and that is expressed by tracking the probe's own wait
  // rather than by picking a second constant that could drift from it.
  const controlTimeoutMs = opts.controlTimeoutMs ?? callbackTimeoutMs;
  const warnings: string[] = [];
  const errors: string[] = [];

  const isStdio = server.transport !== "sse";

  // A holder object, not bare `let`s: the setup below happens inside an
  // async closure past several `await`s, so TypeScript's control-flow
  // narrowing can't see that the assignments have happened by the time
  // `finally` runs — reading mutable properties sidesteps that (real, if
  // unrelated to the code's actual behavior) narrowing limitation.
  const holder: {
    connection: LiveConnection | null;
    sandbox: TargetSandbox | null;
    oracle: CallbackOracle | null;
  } = { connection: null, sandbox: null, oracle: null };

  const result: LiveAuditResult = {
    timestamp: new Date().toISOString(),
    serverName: server.name,
    transportKind: isStdio ? "stdio" : "sse",
    // Starts at never-reached and is earned, rather than starting at
    // "probed" and being downgraded on failure. Every way this function can
    // exit early — a throw, a timeout, a deadline that fires between two
    // awaits — leaves the pessimistic value in place, so the failure mode of
    // forgetting a branch is a scan that under-claims. The opposite default
    // fails towards reporting a target palar never spoke to as one it
    // examined and found clean.
    outcome: "never-reached",
    unreachable: null,
    pid: null,
    sandboxSetupMs: 0,
    containerStartMs: 0,
    connectDurationMs: 0,
    liveTools: [],
    toolDrift: [],
    probes: [],
    poisoningChecks: [],
    oracle: { baseUrl: "" },
    warnings,
    errors,
    durationMs: 0,
  };

  /** Finishes the result as never-reached, without having started anything. */
  const neverReached = (reason: string): LiveAuditResult => {
    result.outcome = "never-reached";
    result.unreachable = { reason };
    errors.push(reason);
    result.durationMs = Date.now() - start;
    return result;
  };

  // Pre-flight, before a lock's worth of Docker state exists: does the
  // declared command name a program that is actually on this disk? This is
  // the check `scan --from-command` has always run at plan time and this
  // path never did, which is how mcp-server-fetch's `python -m
  // mcp_server_fetch` got as far as starting a container and dying inside
  // it as `Cannot find module '/target/python'`. See findProgramToken().
  //
  // SSE targets are exempt: there is no local program, and the command
  // field is not what gets used.
  if (isStdio) {
    if (!server.command) {
      return neverReached(
        `Server "${server.name}" declares no "command", so there is nothing to start over ` +
          "stdio. palar never reached this target and learned nothing about it."
      );
    }
    if (!opts.targetDir) {
      return neverReached(
        `Server "${server.name}" is a stdio target but no mount directory was supplied, so ` +
          "palar refuses to start it. It never reached this target and learned nothing about it."
      );
    }
    const tokens = [server.command, ...(server.args ?? [])];
    if (findProgramToken(tokens, opts.targetDir) === undefined) {
      return neverReached(
        `Server "${server.name}" declares \`${tokens.join(" ")}\`, and none of those tokens ` +
          `names a file that exists under ${opts.targetDir}. The sandbox provides a Node ` +
          "runtime and a read-only mount of that directory — no network, no package manager, " +
          "and no other language runtime — so an invocation naming a program palar cannot see " +
          "(a Python module, a binary on your PATH, an npx/uvx package to be fetched) cannot " +
          "start there. Point the server's \"command\"/\"args\" at an installed entry point " +
          "beside the manifest, e.g. `node node_modules/@scope/server/dist/index.js`."
      );
    }
  }

  // ---- palar's own setup, deliberately OUTSIDE the overall deadline ----
  //
  // Docker is mandatory for stdio: the sandbox (and the container network
  // it creates) has to exist before the oracle starts, because which
  // address the oracle can both bind to and be reached at is a property
  // of the detected Docker backend and that specific network (see
  // sandbox.ts / oracle.ts docstrings). SSE has no local process, so no
  // sandbox is created and the oracle keeps its original loopback/
  // opts.oracleHost behavior.
  //
  // None of this is the target. Building the runtime image on a first run
  // fetches a ~300MB base layer and installs a package into it; on a slow
  // link that alone can outlast any sane scan budget. Racing it against
  // --timeout-ms produced the worst available outcome — palar's own
  // first-run setup, reported as a target that never answered, to a user
  // who has not yet seen palar work once. So the deadline starts below,
  // after the tools are built, and a failure here says what it was.
  let sandbox: TargetSandbox | null = null;
  let oracle: CallbackOracle | null = null;
  const setupStart = Date.now();
  try {
    if (isStdio) {
      sandbox = await TargetSandbox.create(opts.onImageBuild);
      holder.sandbox = sandbox;
    }

    oracle = sandbox
      ? new CallbackOracle(sandbox.oracleBindHost, { advertisedHost: "host.docker.internal" })
      : new CallbackOracle(opts.oracleHost ?? "127.0.0.1");
    await oracle.start();
    holder.oracle = oracle;
    result.oracle = { baseUrl: oracle.baseUrl };

    if (sandbox) {
      await sandbox.installFirewall(oracle.port);
    }
  } catch (err) {
    result.sandboxSetupMs = Date.now() - setupStart;
    if (holder.sandbox) await holder.sandbox.teardown();
    if (holder.oracle) await holder.oracle.stop();
    return neverReached(
      `palar could not prepare its own sandbox for "${server.name}": ${(err as Error).message}. ` +
        "This failed before the target was started, so it is a problem with palar's setup on " +
        "this machine (Docker, the runtime image, the callback listener) rather than anything " +
        "about the server. Nothing was examined."
    );
  }
  result.sandboxSetupMs = Date.now() - setupStart;

  // ---- the scan itself: everything below IS bounded by --timeout-ms ----
  //
  // The deadline is armed HERE, after setup, and that placement is the
  // whole of "setup is not raced by --timeout-ms". Arming it earlier — as
  // this did until a `--timeout-ms 1000` run crashed the process — is worse
  // than merely mis-attributing the time: nothing awaits `overallDeadline`
  // until the Promise.race() far below, so a deadline that fires while
  // setup is still running is an unhandled rejection, which kills the
  // process outright and leaks the sandbox network it had already created.
  // A timer must not start before something is ready to catch it.
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  const overallDeadline = new Promise<never>((_, reject) => {
    deadlineTimer = setTimeout(() => {
      reject(new Error(`live scan exceeded overall timeout of ${overallTimeoutMs}ms`));
    }, overallTimeoutMs);
  });

  // Non-null past the setup block: the only paths out of it either assigned
  // this or returned. Captured in a const so the closure below does not have
  // to re-narrow a mutable binding across its awaits.
  const startedOracle = oracle as CallbackOracle;

  const work = (async () => {
    const connectStart = Date.now();
    const connection = await connectLive(server, {
      targetDir: opts.targetDir,
      connectTimeoutMs: opts.connectTimeoutMs,
      containerStartTimeoutMs: opts.containerStartTimeoutMs,
      sandbox: sandbox ?? undefined,
    });
    holder.connection = connection;
    // Container start is subtracted rather than folded in: the two numbers
    // answer different questions, and only the second is about the target.
    result.containerStartMs = connection.containerStartMs;
    result.connectDurationMs = Date.now() - connectStart - connection.containerStartMs;
    result.pid = connection.pid;

    const listed = await connection.client.listTools();
    const liveTools = listed.tools as unknown as LiveTool[];
    result.liveTools = liveTools.map((t) => ({
      name: t.name,
      ...(typeof t.title === "string" ? { title: t.title } : {}),
      ...(typeof t.description === "string" ? { description: t.description } : {}),
      // Spread in only when the server actually sent an annotations
      // object, so "declared nothing" stays distinguishable from
      // "declared an empty object" downstream.
      ...(typeof t.annotations === "object" && t.annotations !== null
        ? { annotations: t.annotations }
        : {}),
    }));

    // The one place the outcome is earned. Everything above this line can
    // fail in a way that means palar never spoke to the target; past it, a
    // tool list is in hand and whatever happens next is a partial result
    // rather than no result. A failure during probing therefore stays
    // `probed` and lands in `errors` — the probes that did run really ran.
    result.outcome = liveTools.length === 0 ? "no-tools" : "probed";

    const staticByName = new Map(staticTools.map((t) => [t.definition.name, t.definition]));
    const liveNames = new Set(liveTools.map((t) => t.name));
    const toolDrift: ToolDriftEntry[] = [];
    for (const name of staticByName.keys()) {
      if (!liveNames.has(name)) toolDrift.push({ toolName: name, kind: "only-in-static-file" });
    }
    for (const name of liveNames) {
      if (!staticByName.has(name)) toolDrift.push({ toolName: name, kind: "only-in-live-server" });
    }
    result.toolDrift = toolDrift;

    for (const tool of liveTools) {
      const targets = classifyExecutionAdjacentFields(tool);
      const toolProbes: LiveProbeResult[] = [];
      for (const target of targets) {
        toolProbes.push(
          await runOneProbe(connection, startedOracle, tool, target, callbackTimeoutMs)
        );
      }
      result.probes.push(...toolProbes);

      // Ordered deliberately: probes, then the poisoning check, then the
      // control. The poisoning check makes the identical benign call, so
      // running it here — after the payloads, before the control — lets its
      // result seed the control for free. Moving it ahead of the probes to
      // "get the control early" would put a benign call in front of the
      // payload, which is the contamination finalizeToolProbes() exists to
      // avoid.
      const poisoning = await runPoisoningCheck(
        connection,
        tool,
        staticByName,
        result.transportKind,
        controlTimeoutMs
      );
      if (poisoning) result.poisoningChecks.push(poisoning.check);

      await finalizeToolProbes(
        connection,
        tool,
        toolProbes,
        result.transportKind,
        controlTimeoutMs,
        poisoning?.control ?? null
      );
    }
  })();

  try {
    await Promise.race([work, overallDeadline]);
  } catch (err) {
    const message = (err as Error).message;
    errors.push(message);
    // Only a failure BEFORE the tool list arrived means nothing was
    // examined. `outcome` is still at its pessimistic initial value in
    // exactly that case, so this needs no separate flag to consult.
    if (result.outcome === "never-reached") {
      result.unreachable = {
        reason:
          `palar never got a tool list from "${server.name}": ${message}. Nothing was ` +
          "examined, so nothing is known about this target either way.",
      };
    }
  } finally {
    clearTimeout(deadlineTimer);
    if (holder.connection) {
      try {
        await holder.connection.close();
      } catch (err) {
        warnings.push(`failed to cleanly close target: ${(err as Error).message}`);
      }
    }
    if (holder.sandbox) {
      // Defensive and idempotent: connectLive() may have thrown before a
      // connection existed (e.g. the container never started), in which
      // case close() above never ran and never tore the sandbox down.
      // Also covers holder.connection.close() itself throwing before it
      // reached its own sandbox.teardown() call.
      await holder.sandbox.teardown();
    }
    if (holder.oracle) {
      await holder.oracle.stop();
    }
  }

  result.durationMs = Date.now() - start;
  return result;
}
