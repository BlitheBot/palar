/**
 * The benign control call: deciding which tools may receive one, building
 * its arguments, and sending it.
 *
 * ## What a control call is for
 *
 * `rejected` (see status.ts) means "the target returned an error result for
 * our payload". It silently absorbs a second, very different situation:
 * the tool could not run here AT ALL, so no request was ever attempted and
 * the payload was never the thing being answered. playwright-mcp's two
 * probes were counted `rejected` when Chromium was simply absent from the
 * sandbox container — the browser never launched, nothing was tested, and
 * the report read as reassurance about a tool that had not been exercised.
 *
 * A control call separates those two without reading a single character of
 * the target's error text: send the SAME tool the same shape of call with
 * schema-valid benign arguments and no payload. If that errors too, the
 * probe's error was not a refusal OF THE PAYLOAD. That is an outcome
 * comparison, not a string match, which is the whole reason it is
 * admissible here — status.ts argues at length against pattern-matching
 * free-form error prose, and this instrument does not.
 *
 * ## The gate, and why hints can only ever subtract
 *
 * A benign call is not a no-op. `delete_file` with schema-valid filler
 * deletes a file. So the question "which tools may receive a control call"
 * has to be answered before any of this is worth having.
 *
 * `destructiveHint` and `readOnlyHint` are now threaded through to here,
 * and they are exactly the wrong thing to lean on for permission, because
 * a server can lie in either direction and the two lies do not cost the
 * same:
 *
 *   - A SAFETY claim (`readOnlyHint: true`, `destructiveHint: false`) that
 *     is a lie gets palar to call something destructive. The cost is a
 *     real, unrecoverable side effect on someone else's machine.
 *   - A DANGER claim (`destructiveHint: true`) that is a lie gets palar to
 *     skip a control call it could have run. The cost is a coverage gap,
 *     which shows up in the report as `rejected (not controlled)` and can
 *     be recovered by looking.
 *
 * So the rule this module enforces: **an annotation may only ever subtract
 * permission, never grant it.** A safety claim is not a licence to call. A
 * danger claim is an absolute veto. That is the same asymmetry
 * core/annotations.ts already applies to reading hints at all (absence
 * degrades to "not declared", never to a value), for the same reason —
 * a declaration is evidence only in the direction that costs the declarer.
 *
 * Note the consequence, which is intended: since hints cannot grant
 * permission, and the spec's default for an UNDECLARED `destructiveHint`
 * is `true`, silence is not permission either. Permission has to come from
 * somewhere that is not the server's own say-so.
 *
 * ## What actually grants permission: the sandbox, and only the sandbox
 *
 * For a stdio target, the tool is already running inside the ephemeral
 * container liveScan.ts sets up: read-only mount, dropped capabilities,
 * no egress but palar's own oracle, and an unconditional teardown in
 * `finally`. A destructive tool in there is destructive to a container
 * that is about to cease existing. The blast radius is already bounded,
 * and it is bounded by construction rather than by trusting the target.
 *
 * An SSE target has no sandbox at all — there is no local process to put
 * one around. A control call to a remote `send_email` sends an email, to
 * a real recipient, on a machine palar does not control. So SSE targets
 * are gated OFF here, with no opt-in flag: there is no version of that
 * call whose blast radius palar can bound.
 *
 * The formerly-recorded incoherence — the probe loop sending the full
 * injection set to SSE targets while this benign control was gated off — is
 * now resolved, on a DIFFERENT axis than this gate uses. eligibility.ts
 * splits SSE by loopback-vs-remote: a remote SSE target is enumerated only
 * (no payload), and a loopback one is probed. This gate stays on the
 * stdio-vs-sse line because it governs SANDBOXING, and a loopback SSE
 * process is no more sandboxed than a remote one — so a benign control call
 * to it is still a real, unbounded side effect and still withheld. Payloads
 * reach a loopback SSE target because the operator pointed palar at their
 * own machine and asked; an extra benign disambiguation call is not part of
 * that ask and is not granted by it.
 *
 * ## The verb list, which is palar's own
 *
 * The third layer subtracts on palar's own reading of the tool NAME,
 * independent of anything the server claims about itself. It is a
 * heuristic and it is meant to be: it only ever withholds a call, so its
 * failure mode is a probe that stays `rejected (not controlled)` — the
 * status quo before this module existed.
 */
import type { LiveConnection } from "./connector.js";
import { readHint, type AnnotatedTool } from "../core/annotations.js";
import { isConstrained } from "../rules/input-validation.js";
import type { JSONSchemaProperty } from "../core/types.js";
import type { LiveTool } from "./probes.js";
import type { ControlCall, ToolCallCapture } from "./types.js";

/**
 * Verb segments that mark a tool name as too consequential to call with
 * filler, whatever the server says about it. Matched as substrings of the
 * lowercased name: a tool called `delete_file` and one called
 * `filesDeleteBatch` are the same problem.
 *
 * Deliberately broad. Every entry here costs at most coverage, and the
 * asymmetry that governs the whole module applies to this list too — a
 * missing verb risks a real side effect, a spurious one risks a probe
 * reading exactly as it already did.
 */
export const DESTRUCTIVE_NAME_SEGMENTS = [
  "delete",
  "remove",
  "destroy",
  "drop",
  "purge",
  "truncate",
  "wipe",
  "erase",
  "kill",
  "terminate",
  "unlink",
  "rmdir",
  "write",
  "overwrite",
  "replace",
  "move",
  "rename",
  "send",
  "publish",
  "post",
  "email",
  "commit",
  "push",
  "deploy",
  "execute",
  "exec",
  "spawn",
  "run",
  "shell",
  "eval",
  // Execution verbs that are not themselves the word "run": these are the
  // gap the tests caught. desktop-commander's `start_process` — the single
  // most dangerous tool in palar's sample — matched nothing in an earlier
  // version of this list, which is exactly the failure mode a name
  // heuristic is prone to and the reason it is only ever one of three
  // layers.
  "start",
  "launch",
  "process",
  "command",
  "script",
  "restart",
  "stop",
  "sudo",
  "chmod",
  "chown",
  // Mutating verbs. Inside the sandbox these are cheap, but the gate is
  // meant to hold even if the containment assumptions below it stop being
  // true, so they are vetoed on the name too.
  "create",
  "update",
  "insert",
  "patch",
  "upload",
  "install",
  "uninstall",
  "revoke",
  "grant",
  "transfer",
  "pay",
  "charge",
] as const;

/** Why a control call was or was not sent. Carried into the report verbatim. */
export interface ControlGateDecision {
  allowed: boolean;
  /** Reader-facing sentence fragment, e.g. "the tool name contains \"delete\"". */
  reason: string;
}

/**
 * Whether this tool may receive a benign control call.
 *
 * Order is meaningful only for which reason a reader is shown; the vetoes
 * are independent and any one of them is sufficient. The transport check
 * is first because it is the one that is about palar's own containment
 * rather than about the tool.
 */
export function controlGateDecision(
  tool: AnnotatedTool & { name: string },
  transportKind: "stdio" | "sse"
): ControlGateDecision {
  if (transportKind !== "stdio") {
    return {
      allowed: false,
      reason:
        "this is an SSE target, so there is no sandbox around it — a benign call would be a " +
        "real call to a real remote server, and palar cannot bound what it does",
    };
  }

  // A danger claim is trusted BECAUSE it is against the declarer's
  // interest. A safety claim is never consulted: see the module docstring.
  if (readHint(tool, "destructiveHint") === true) {
    return {
      allowed: false,
      reason:
        'the server declared `destructiveHint: true` for this tool. palar takes a declared ' +
        "danger claim at face value (it costs the declarer something to make it) even though " +
        "it never takes a declared SAFETY claim as permission",
    };
  }

  const lowered = tool.name.toLowerCase();
  const hit = DESTRUCTIVE_NAME_SEGMENTS.find((segment) => lowered.includes(segment));
  if (hit) {
    return {
      allowed: false,
      reason:
        `the tool name contains "${hit}", which palar reads as too consequential to call with ` +
        "filler arguments — this is palar's own judgement about the name, not something the " +
        "server declared",
    };
  }

  return { allowed: true, reason: "stdio target, no declared destructive hint, name is not on palar's verb list" };
}

/**
 * Schema-satisfying benign arguments for a whole tool: required properties
 * only, filler on each, and a plain sentence where the schema genuinely
 * accepts free-form prose.
 *
 * Required-only for the same reason buildProbeArguments() is (see its
 * docstring): an optional property is a knob, and inventing a value for a
 * knob changes what the tool does. For a control call that would be worse
 * than for a probe — the control's entire job is to establish whether the
 * tool runs in its ordinary configuration, and a filled-in optional makes
 * it a different call than the probe it is supposed to be the control for.
 */
export function buildBenignArguments(
  tool: LiveTool,
  freeFormText: string,
  benignValueFor: (prop: JSONSchemaProperty | undefined) => unknown
): Record<string, unknown> {
  const properties = tool.inputSchema.properties ?? {};
  const required = new Set(
    Array.isArray(tool.inputSchema.required)
      ? tool.inputSchema.required.filter((n): n is string => typeof n === "string")
      : []
  );
  const args: Record<string, unknown> = {};
  for (const name of Object.keys(properties)) {
    if (!required.has(name)) continue;
    const prop = properties[name];
    const freeFormString =
      typeof prop === "object" && prop !== null && prop.type === "string" && !isConstrained(prop);
    args[name] = freeFormString ? freeFormText : benignValueFor(prop);
  }
  return args;
}

/**
 * Sends one control call, bounded by its own timeout.
 *
 * The timeout exists because the cost of this feature is not latency, it
 * is BLOCKING. A tool that launches a browser or waits out its own long
 * internal HTTP timeout would otherwise add that whole wait to the scan.
 * Callers pass a bound at or below `callbackTimeoutMs`, so a controlled
 * probe costs at most about what one probe already costs.
 *
 * A control that times out is a control that told us nothing, so it
 * resolves to `errored` rather than to a clean result. Same direction as
 * everything else here: when in doubt, do not reassure.
 */
export async function sendControlCall(
  connection: LiveConnection,
  toolName: string,
  args: Record<string, unknown>,
  timeoutMs: number,
  captureToolResult: (result: unknown) => ToolCallCapture
): Promise<ControlCall> {
  const started = Date.now();
  // Cleared in `finally` rather than left to expire. An uncleared timer
  // keeps the event loop alive for its full duration after a call that
  // returned in milliseconds, which on a scan with many controlled tools
  // would hold the process open well past the work being done.
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      connection.client.callTool({ name: toolName, arguments: args }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`control call exceeded ${timeoutMs}ms`)),
          timeoutMs
        );
      }),
    ]);
    const capture = captureToolResult(result);
    return {
      attempted: true,
      outcome: capture.isError === true ? "errored" : "succeeded",
      args,
      toolCall: capture,
      durationMs: Date.now() - started,
    };
  } catch (err) {
    // A transport failure or a timeout both mean the same thing here: the
    // benign call did not come back clean, so the payload is not the
    // explanation for the probe's error either.
    return {
      attempted: true,
      outcome: "errored",
      args,
      toolCall: { error: (err as Error).message },
      durationMs: Date.now() - started,
    };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}
