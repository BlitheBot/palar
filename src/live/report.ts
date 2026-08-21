/**
 * Renders the live-scan report, cross-referenced against the static
 * AuditResult for display purposes only — the static Finding[] array
 * itself is never mutated (see types.ts docstring for why).
 *
 * The whole point of this pass: CONFIRMED, CONTRADICTED DECLARATIONS,
 * NOT-TESTED, ATTEMPTED-REJECTED, ATTEMPTED-UNCONFIRMED, and STATIC-ONLY
 * are kept as visibly separate sections, never flattened back into one
 * undifferentiated finding list.
 * They are printed in the same order status.ts resolves them, so the
 * strongest claim is always the one at the top.
 *
 * NOT TESTED is not a result at all and is worded so it cannot be read as
 * one: the probe's call failed with palar's own arguments already known to
 * violate the target's published schema, so the field was never exercised.
 * Its static finding stays listed under STATIC-ONLY for that reason — the
 * live pass produced no coverage of it.
 *
 * REJECTED is a provenance label, not a verdict (see status.ts): the probe
 * ran, the target answered, and the answer was an error result. It does not
 * downgrade the finding's severity and it does not remove the finding --
 * severity belongs to the static analyzer and is left alone. Because the
 * same isError flag covers an argument-validation bounce, a handler-level
 * refusal, AND a successful injection whose command exited nonzero, this
 * renderer prints the target's own response text verbatim next to the
 * status rather than classifying it: the reader distinguishes those cases
 * from the evidence, and palar does not guess on their behalf.
 */
import type { AuditResult, Finding } from "../core/types.js";
import { CONTRADICTION_RULE_ID } from "./annotation-contradiction.js";
import type { LiveAuditResult, LiveProbeResult, PoisoningLiveCheck } from "./types.js";

function parseToolFieldPath(jsonPath: string | undefined): { toolName: string; fieldPath: string } | null {
  if (!jsonPath) return null;
  const m = /^tools\["([^"]+)"\]\.inputSchema\.properties\.(.+)$/.exec(jsonPath);
  if (!m) return null;
  return { toolName: m[1]!, fieldPath: m[2]! };
}

function parseToolDescriptionPath(jsonPath: string | undefined): string | null {
  if (!jsonPath) return null;
  const m = /^tools\["([^"]+)"\]\.description$/.exec(jsonPath);
  return m ? m[1]! : null;
}

function formatCodePoint(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
}

const PROBE_LABELS: Record<LiveProbeResult["status"], string> = {
  confirmed: "CONFIRMED",
  "not-tested": "NOT TESTED — PALAR'S OWN ARGUMENTS WERE INVALID",
  inconclusive: "INCONCLUSIVE — THE TOOL COULD NOT RUN HERE AT ALL",
  rejected: "ATTEMPTED — REJECTED BY TARGET",
  unconfirmed: "ATTEMPTED — UNCONFIRMED",
};

/**
 * The two tiers of `rejected`, rendered into the heading itself.
 *
 * A reader who knows palar runs control calls must not read every
 * REJECTED as controlled. A rejection backed by a clean control is a
 * materially stronger observation than one where the control was withheld
 * — the first knows the tool runs, the second is exactly where the report
 * was before control calls existed. Collapsing them would launder the
 * weaker into the stronger.
 */
function rejectedTier(p: LiveProbeResult): string {
  if (p.status !== "rejected") return "";
  return p.control?.attempted === true ? " (control call ran clean)" : " (NOT CONTROLLED)";
}

function renderArgumentIssues(p: LiveProbeResult): string[] {
  if (p.argumentIssues.length === 0) return [];
  const lines: string[] = [""];
  lines.push("  Constraints palar could not satisfy in this call:");
  for (const i of p.argumentIssues) {
    lines.push(
      `  - \`${i.fieldPath}\`${i.isTarget ? " (the probed field itself)" : ""} ${i.detail}`
    );
  }
  return lines;
}

/**
 * The control call's own line, plus — for an inconclusive probe — the
 * caveat that palar's own sandbox is the leading suspect.
 *
 * That last part is not optional and not a source comment. status.ts's
 * honest-limit list records six causes that `inconclusive` cannot tell
 * apart, and cause (2) is that palar's OWN isolation (no egress, read-only
 * mount, dropped capabilities, no DNS) broke the tool. On the evidence so
 * far that is the likeliest one. A reader who sees "the tool could not run
 * here" and concludes something about the target — rather than about the
 * container palar put it in — has been misled by a status that exists to
 * stop exactly that kind of misreading.
 */
function renderControl(p: LiveProbeResult): string[] {
  const control = p.control;
  if (!control) return [];
  const lines: string[] = [];

  if (!control.attempted) {
    lines.push(
      `- **Control call:** not sent — ${control.reason}.`
    );
  } else {
    const outcome =
      control.outcome === "succeeded"
        ? "came back CLEAN"
        : "ERRORED too";
    const body =
      "error" in control.toolCall
        ? `failed — ${control.toolCall.error}`
        : control.toolCall.textPreview || "(empty)";
    lines.push(
      `- **Control call:** benign, payload-free call to the same tool ${outcome} ` +
        `(${control.durationMs}ms) with \`${JSON.stringify(control.args)}\` — ${body}`
    );
  }

  if (p.status === "inconclusive") {
    lines.push("");
    lines.push(
      "  palar sent this tool a second call with schema-valid benign arguments and NO payload, " +
        "and that errored too. So the tool did not run here at all, and the error above is not " +
        "the target refusing the payload — it is not evidence about the payload either way. " +
        "This is compared as an outcome, not matched against the error text."
    );
    lines.push("");
    lines.push(
      "  **The leading suspect is palar's own sandbox, not the target.** The container denies " +
        "the target all network egress, mounts its directory read-only, drops capabilities and " +
        "gives it no DNS resolver — any tool needing one of those fails here and would work " +
        "fine outside. Other causes this cannot distinguish: a dependency missing from the " +
        "container (a browser that was never installed), a tool that is simply broken, one that " +
        "refuses every unrecognized caller, a rule the schema never declared that the benign " +
        "filler also trips, or palar's own earlier payload having wedged the handler. What it " +
        "rules out is only this: the payload is not the explanation."
    );
    lines.push("");
    lines.push(
      "  The static finding for this field stands exactly as the static pass wrote it. Nothing " +
        "here raises or lowers it, and this probe is NOT counted as coverage."
    );
  }
  return lines;
}

function renderProbe(p: LiveProbeResult): string {
  const lines: string[] = [];
  const label = PROBE_LABELS[p.status];
  lines.push(`#### [${label}${rejectedTier(p)}] ${p.toolName}.${p.fieldPath} (${p.kind})`);
  lines.push("");
  lines.push(`- **Why probed:** ${p.reason}`);
  lines.push(`- **Payload sent:** \`${p.payload}\``);
  lines.push(
    `- **Callback:** ${
      p.callback
        ? `received at ${p.callback.receivedAt} from ${p.callback.remoteAddress ?? "unknown"}`
        : `none within ${p.callbackTimeoutMs}ms`
    }`
  );
  const call = p.toolCall;
  if ("error" in call) {
    lines.push(`- **Tool call:** failed — ${call.error}`);
  } else {
    const heading =
      p.status === "rejected"
        ? "Rejected with (isError=true)"
        : `Tool call response${call.isError ? " (isError=true)" : ""}`;
    lines.push(`- **${heading}:** ${call.textPreview || "(empty)"}`);
  }
  lines.push(...renderControl(p));
  // Listed for every status, not only not-tested: on a probe that
  // succeeded anyway it is the observation that the target does not
  // enforce a constraint it advertises, which is worth seeing.
  lines.push(...renderArgumentIssues(p));
  if (p.status === "not-tested") {
    lines.push("");
    lines.push(
      "  This call failed, and palar's own arguments already violated the schema this target " +
        "published — so the failure is explained without the payload, and the probed field was " +
        "never exercised. Nothing here is evidence about the target either way: it is neither a " +
        "refusal nor a clean result, and the static finding stands exactly as it did before the " +
        "scan ran."
    );
    lines.push("");
    lines.push(
      "  The mismatch is computed from the target's declared schema before the call is sent, " +
        "not read out of the error text above. That makes it exact for constraints the target " +
        "DECLARED and blind to ones it only enforces — a probe bounced by an undeclared rule " +
        "still reads REJECTED, because separating those would mean guessing from free-form " +
        "error strings."
    );
  } else if (p.status === "rejected") {
    lines.push("");
    lines.push(
      "  The target returned an error result for this payload, quoted verbatim above. That " +
        "is NOT proof the tool is safe: it rejected THIS ONE input, which says nothing about " +
        "any other input. The severity of the corresponding static finding is deliberately " +
        "left unchanged."
    );
    lines.push("");
    lines.push(
      p.control?.attempted === true
        ? "  A benign, payload-free control call to this same tool came back clean, so the " +
            "tool does run in this environment and the error above is the target answering " +
            "THIS payload rather than failing to start. That is what distinguishes this entry " +
            "from an INCONCLUSIVE one."
        : "  **No control call was sent for this tool**, so palar has not established that the " +
            "tool can run here at all. If it cannot — a missing dependency, palar's own " +
            "sandbox restrictions — then the error above is not a refusal of the payload and " +
            "this entry should be read as INCONCLUSIVE rather than as the target pushing " +
            "back. See the control-call line above for why it was withheld."
    );
    lines.push("");
    lines.push(
      "  Read the response text to tell these apart — the status alone cannot, and palar " +
        "does not guess: (1) input validation rejected the payload; (2) validation bounced " +
        "the call on a rule the schema never declared, before the tool's handler ever ran " +
        "(a bounce on a DECLARED rule is caught before sending and reads NOT TESTED " +
        "instead); (3) the handler ran and refused for an unrelated reason; (4) the injected " +
        "command RAN and exited nonzero. Case (4) is evidence FOR injection, and it reaches " +
        "this section only when no callback arrived to prove it — had one arrived, this " +
        "would read CONFIRMED."
    );
  } else if (p.status === "unconfirmed") {
    lines.push("");
    lines.push(
      "  No callback does not mean safe — it can also mean the payload failed for an " +
        "unrelated reason, or egress was blocked. Reported as unconfirmed, never silently " +
        "upgraded and never treated as a negative result."
    );
  }
  return lines.join("\n");
}

function renderPoisoning(check: PoisoningLiveCheck): string {
  const lines: string[] = [];
  const points = check.codePoints.map(formatCodePoint).join(", ");
  lines.push(`#### [LIVE-VERIFIED] ${check.toolName} description carries hidden code points (${points})`);
  lines.push("");
  if (check.liveDescriptionMatchesStatic === true) {
    lines.push(
      "- The live server's listTools() response matches the static JSON file byte-for-byte " +
        "— the poisoned description is genuinely served, not just present in a file that " +
        "might be stale or never actually loaded."
    );
  } else if (check.liveDescriptionMatchesStatic === false) {
    lines.push(
      "- The live description DIFFERS from the static JSON file — the static scanner's " +
        "finding does not reflect what this server currently serves."
    );
  } else {
    lines.push(
      "- No static definition was available to cross-check against; this was observed only " +
        "in the live listTools() response."
    );
  }
  lines.push(
    "- No oracle-style confirmation exists for prompt-injection/tool-poisoning findings in " +
      "this pass: the injected text targets an LLM's judgment, and palar's live scanner is " +
      "not an LLM, so there is nothing here for it to be tricked into doing. Calling the tool " +
      "directly only exercises the tool's own (non-agentic) code path, captured below."
  );
  const call = check.toolCall;
  if (check.withheldReason) {
    // The finding itself is unaffected: it rests on the description bytes,
    // which are already in hand. Only the behavioural sample is missing,
    // and an unexplained absence is worse than a stated one.
    lines.push(
      `- **Direct tool call:** NOT MADE — ${check.withheldReason}. The poisoning finding above ` +
        `stands regardless: it rests on the description this server served, not on calling ` +
        `the tool. What is missing is only a sample of the tool's own code path.`
    );
  } else if (call && "error" in call) {
    lines.push(`- **Direct tool call:** failed — ${call.error}`);
  } else if (call) {
    lines.push(`- **Direct tool call response:** ${call.textPreview || "(empty)"}`);
  }
  return lines.join("\n");
}

/**
 * The whole report for a target palar never spoke to.
 *
 * Deliberately NOT the ordinary report with empty sections. The ordinary
 * report's shape is a claim in itself — a page of "CONFIRMED: None.",
 * "REJECTED: None.", "UNCONFIRMED: None." reads as a target that was
 * exercised and came back clean, which is the exact opposite of what
 * happened. So the sections that would be empty are not printed at all, and
 * what replaces them says why there is nothing and what it does not mean.
 * Same wording as `scan`'s never-reached, because it is the same event.
 */
function renderUnreached(live: LiveAuditResult): string {
  const lines: string[] = [];
  lines.push("# palar LIVE audit report");
  lines.push("");
  lines.push(`- **Timestamp:** ${live.timestamp}`);
  lines.push(`- **Server:** ${live.serverName} (${live.transportKind})`);
  lines.push(
    `- **Outcome:** ${
      live.outcome === "never-reached"
        ? "NEVER REACHED — no probe was sent, no score"
        : "connected, zero tools — nothing to probe, no score"
    }`
  );
  lines.push(`- **Total duration:** ${live.durationMs}ms`);
  lines.push("");
  lines.push("## Nothing was examined on this target");
  lines.push("");
  if (live.outcome === "never-reached") {
    lines.push(live.unreachable?.reason ?? "palar never obtained a tool list from this target.");
    lines.push("");
    lines.push(
      "palar examined nothing here, which is not the same as finding nothing. No tool was " +
        "called, no payload was built, and no probe result exists to interpret — so this " +
        "report makes no claim whatsoever about the target's security posture, in either " +
        "direction. Any static findings listed by the same run describe the definition FILES " +
        "on disk; they were not verified against this server, because this server never " +
        "answered."
    );
  } else {
    lines.push(
      "The server completed the MCP handshake and reported zero tools, so there were no " +
        "tools to probe. That is a real observation about the running server — it answered — " +
        "but it is not coverage: nothing was exercised, and no score is reported for it."
    );
  }
  lines.push("");
  // The reason is already the body of this report, so an Errors section
  // repeating it verbatim is noise. Only errors that say something the
  // paragraph above did not are worth a second appearance.
  const extraErrors = live.errors.filter((e) => e !== live.unreachable?.reason);
  if (extraErrors.length > 0) {
    lines.push("## Errors");
    lines.push("");
    for (const e of extraErrors) lines.push(`- ${e}`);
    lines.push("");
  }
  return lines.join("\n");
}

export function renderLiveMarkdownReport(staticResult: AuditResult, live: LiveAuditResult): string {
  // Before anything else: a run that never got a tool list gets a report
  // that cannot be mistaken for one that did. See renderUnreached().
  if (live.outcome !== "probed") return renderUnreached(live);

  const lines: string[] = [];
  lines.push("# palar LIVE audit report");
  lines.push("");
  lines.push(`- **Timestamp:** ${live.timestamp}`);
  lines.push(
    `- **Server:** ${live.serverName} (${live.transportKind}${
      live.pid !== null ? `, pid ${live.pid}` : ""
    })`
  );
  // Three numbers, not one, because only the last is about the server. A
  // reader looking at a slow scan needs to know whether the target was slow
  // or palar was.
  lines.push(
    `- **palar setup:** ${live.sandboxSetupMs}ms (Docker preflight, images, network, oracle)` +
      (live.transportKind === "stdio" ? `; container start ${live.containerStartMs}ms` : "")
  );
  lines.push(
    `- **Target handshake:** ${live.connectDurationMs}ms ` +
      `(measured from the container running, so it is the server's latency alone)`
  );
  lines.push(`- **Live tools discovered:** ${live.liveTools.length}`);
  lines.push(
    `- **Oracle listener:** ${live.oracle.baseUrl} (${
      live.transportKind === "stdio"
        ? "bound to the address this scan's sandbox container reaches the host through — the sandbox's one permitted egress destination, everything else rejected"
        : "loopback-only"
    } — see limitations below)`
  );
  lines.push(`- **Total duration:** ${live.durationMs}ms`);
  lines.push("");

  if (live.errors.length > 0) {
    lines.push("## Errors");
    lines.push("");
    for (const e of live.errors) lines.push(`- ${e}`);
    lines.push("");
  }

  if (live.toolDrift.length > 0) {
    lines.push("## Tool drift: static file vs. live server");
    lines.push("");
    lines.push(
      "Something purely static analysis cannot see — what the running server actually " +
        "reports vs. what its declared JSON file says."
    );
    lines.push("");
    for (const d of live.toolDrift) {
      lines.push(
        `- **${d.toolName}**: ${
          d.kind === "only-in-static-file"
            ? "declared in the static file but NOT returned by the live server (stale/dead definition, or the server never registered it)"
            : "returned by the live server but NOT declared in any static file (undeclared/shadow tool)"
        }`
      );
    }
    lines.push("");
  }

  const confirmed = live.probes.filter((p) => p.status === "confirmed");
  const notTested = live.probes.filter((p) => p.status === "not-tested");
  const inconclusive = live.probes.filter((p) => p.status === "inconclusive");
  const rejected = live.probes.filter((p) => p.status === "rejected");
  const unconfirmed = live.probes.filter((p) => p.status === "unconfirmed");

  // The coverage headline, stated before any bucket. "N of M probes
  // actually exercised the field" is the one number that separates a scan
  // that looked from a scan that only ran, and burying it under the
  // per-status sections is how a run where almost nothing was exercised
  // reads as a clean run. Deliberately NOT a pass/fail threshold: a
  // majority cliff would be a magic number, so the count is reported and
  // the reader draws the line.
  const exercised = live.probes.filter(
    (p) => p.status !== "not-tested" && p.status !== "inconclusive"
  );
  if (live.probes.length > 0) {
    lines.push("## COVERAGE");
    lines.push("");
    const unexamined = live.probes.length - exercised.length;
    lines.push(
      `**${exercised.length} of ${live.probes.length} probe(s) actually exercised the field.** ` +
        `${notTested.length} NOT TESTED (palar's own arguments violated the target's declared ` +
        `schema); ${inconclusive.length} INCONCLUSIVE (the tool could not run here at all). ` +
        `Those ${unexamined} probe(s) learned nothing about the target in either direction, ` +
        `and their static findings remain exactly as the static pass wrote them.`
    );
    lines.push("");
    if (exercised.length === 0) {
      lines.push(
        "Every probe in this scan fell into one of those two buckets. That is not a clean " +
          "result; it is no result."
      );
      lines.push("");
    }
  }

  lines.push("## CONFIRMED — oracle callback received");
  lines.push("");
  lines.push(
    `${confirmed.length} finding(s) proven via real out-of-band callback: the crafted payload ` +
      `was sent to the live tool over a real MCP connection, and something the target did — ` +
      `directly or via a shell command it ran — reached back to palar's local listener.`
  );
  lines.push("");
  if (confirmed.length === 0) {
    lines.push("None.");
    lines.push("");
  } else {
    for (const p of confirmed) {
      lines.push(renderProbe(p));
      lines.push("");
    }
  }

  // Placed here, directly under CONFIRMED, because it rests on the same
  // callbacks and on nothing else. Its natural-looking home — the
  // STATIC-ONLY list, which collects every finding no probe covered — is
  // where it must NOT go: that section's heading says no live probe
  // exists for the class, and this class exists only because one did.
  const contradictions = staticResult.findings.filter(
    (f: Finding) => f.ruleId === CONTRADICTION_RULE_ID
  );
  if (contradictions.length > 0) {
    lines.push("## CONTRADICTED DECLARATIONS — the target's own annotations vs. what it did");
    lines.push("");
    lines.push(
      `${contradictions.length} tool(s) whose declared MCP annotations are refuted by a ` +
        `callback above. Both halves were read rather than inferred: the claim came from ` +
        `the server's own listTools() response, and the behaviour from a nonce that ` +
        `reached palar's listener. A hint the server never declared is never counted ` +
        `here — there is no claim to contradict.`
    );
    lines.push("");
    lines.push(
      `This matters separately from the injection itself: annotations are what a client ` +
        `reads to decide whether to ask you before calling a tool. A false one does not ` +
        `just misdescribe the tool, it removes the prompt you would have declined at.`
    );
    lines.push("");
    for (const f of contradictions) {
      lines.push(`#### [${f.severity.toUpperCase()} · CONFIRMED] ${f.ruleId}: ${f.title}`);
      lines.push("");
      lines.push(`- ${f.detail}`);
      if (f.remediation) lines.push(`- **Remediation:** ${f.remediation}`);
      lines.push("");
    }
  }

  if (live.poisoningChecks.length > 0) {
    lines.push("## LIVE-VERIFIED — present on the running server (no oracle equivalent for this class)");
    lines.push("");
    for (const c of live.poisoningChecks) {
      lines.push(renderPoisoning(c));
      lines.push("");
    }
  }

  lines.push("## NOT TESTED — the probe never reached the field");
  lines.push("");
  lines.push(
    `${notTested.length} probe(s) whose call failed while palar's own arguments already ` +
      `violated the schema this target published. The failure is explained by palar's input, ` +
      `so the probed field was never exercised and NOTHING was learned about it. These are ` +
      `not results: read them as coverage palar did not achieve.`
  );
  lines.push("");
  lines.push(
    `Reported separately rather than as rejections because the difference matters in exactly ` +
      `the wrong direction: a probe that dies on palar's filler value looks, in the REJECTED ` +
      `section, like a target that pushed back. Each entry's static finding therefore also ` +
      `stays listed under STATIC-ONLY below — the live pass did not settle it.`
  );
  lines.push("");
  if (notTested.length === 0) {
    lines.push("None.");
    lines.push("");
  } else {
    for (const p of notTested) {
      lines.push(renderProbe(p));
      lines.push("");
    }
  }

  lines.push("## ATTEMPTED — REJECTED BY TARGET");
  lines.push("");
  lines.push(
    `${rejected.length} probe(s) that the target ANSWERED WITH AN ERROR. The probe really ran ` +
      `and the server really replied — this section never contains a tool that was not reached, ` +
      `because a probe that never ran produces no entry at all and its static finding stays in ` +
      `STATIC-ONLY below.`
  );
  lines.push("");
  lines.push(
    `This is NOT a clean bill of health and no severity was changed on account of it. The ` +
      `target refused these specific payloads; it may well accept others. Each entry quotes ` +
      `the target's own error text, which is the only thing that distinguishes a bounce on a ` +
      `rule the schema never declared from a handler-level refusal — and from an injected ` +
      `command that ran and exited nonzero. A bounce on a rule the target DID declare is ` +
      `caught before the call is sent and appears under NOT TESTED, not here.`
  );
  lines.push("");
  if (rejected.length === 0) {
    lines.push("None.");
    lines.push("");
  } else {
    for (const p of rejected) {
      lines.push(renderProbe(p));
      lines.push("");
    }
  }

  lines.push("## ATTEMPTED — UNCONFIRMED");
  lines.push("");
  lines.push(
    `${unconfirmed.length} probe(s) sent to the live tool that produced no callback within the ` +
      `timeout AND no error result — the target accepted the payload and simply said nothing ` +
      `back. This is NOT the same as "safe" — see each entry's caveat.`
  );
  lines.push("");
  if (unconfirmed.length === 0) {
    lines.push("None.");
    lines.push("");
  } else {
    for (const p of unconfirmed) {
      lines.push(renderProbe(p));
      lines.push("");
    }
  }

  lines.push("## INCONCLUSIVE — the tool could not run here at all");
  lines.push("");
  lines.push(
    `${inconclusive.length} probe(s) whose error is not attributable to the payload: a second, ` +
      `benign, payload-free call to the same tool errored too. Nothing about the target's ` +
      `handling of the payload was learned, in either direction — and the leading suspect is ` +
      `palar's own sandbox (no egress, read-only mount, dropped capabilities, no DNS), not the ` +
      `target. These are NOT counted as coverage and move no severity.`
  );
  lines.push("");
  if (inconclusive.length === 0) {
    lines.push("None.");
    lines.push("");
  } else {
    for (const p of inconclusive) {
      lines.push(renderProbe(p));
      lines.push("");
    }
  }

  // Neither a not-tested nor an inconclusive probe is counted as coverage
  // here, for the same reason: the field was never exercised, so the static
  // finding on it is still unsettled and belongs in the unexamined bucket.
  // They appear in both sections — once with the evidence of what went
  // wrong, once in the list of what remains unverified — which is the
  // honest pair.
  const probedPairs = new Set(
    live.probes
      .filter((p) => p.status !== "not-tested" && p.status !== "inconclusive")
      .map((p) => `${p.toolName}::${p.fieldPath}`)
  );
  const poisonedTools = new Set(live.poisoningChecks.map((c) => c.toolName));
  const staticOnly = staticResult.findings.filter((f: Finding) => {
    // Rendered in full under CONTRADICTED DECLARATIONS above. Listing it
    // here too would file a callback-proven finding under a heading that
    // says no live probe exists for its class.
    if (f.ruleId === CONTRADICTION_RULE_ID) return false;
    const tf = parseToolFieldPath(f.location.jsonPath);
    if (tf && probedPairs.has(`${tf.toolName}::${tf.fieldPath}`)) return false;
    const descTool = parseToolDescriptionPath(f.location.jsonPath);
    if (descTool && poisonedTools.has(descTool) && f.ruleId === "TS-001") return false;
    return true;
  });

  lines.push("## STATIC-ONLY — no live probe exists for this class yet");
  lines.push("");
  lines.push(
    `${staticOnly.length} finding(s) from the static analyzer with no dynamic confirmation ` +
      `attempted in this pass (credential scanning, network-posture config, schema meta-` +
      `validation, description hygiene, and non-top-level or non-string-keyword fields) — ` +
      `plus any field whose probe is listed under NOT TESTED or INCONCLUSIVE above, since ` +
      `neither of those probes exercised the field it was aimed at.`
  );
  lines.push("");
  for (const f of staticOnly) {
    lines.push(`- [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.title}`);
  }
  lines.push("");

  lines.push("## Limitations of this pass (not overselling what ran)");
  lines.push("");
  lines.push(
    "- The oracle is a loopback HTTP listener, not external DNS/HTTP collaborator " +
      "infrastructure — it proves reach to the scanning host's own network, not reach to " +
      "genuine external infrastructure (e.g. a real cloud metadata endpoint reachable only " +
      "from inside someone else's network)."
  );
  if (live.transportKind === "stdio") {
    lines.push(
      "- The target ran inside an ephemeral, network-restricted Docker container (read-only " +
        "mount, dropped capabilities, resource limits, no working DNS resolver, and egress — " +
        "both forwarded and host-destined — restricted to this scan's own oracle). That is " +
        "container isolation, not a VM or gVisor — a kernel-level container escape is not " +
        "mitigated, and these containment properties were verified on Docker Desktop, not on " +
        "a native Linux Engine or nftables-only host. See README.md's \"Live scanning\" " +
        "section for the full list of what is and isn't covered."
    );
  } else {
    lines.push(
      "- SSE targets connect to an already-running remote server — there is no local process " +
        "for palar to sandbox here."
    );
  }
  lines.push("");

  if (live.warnings.length > 0) {
    lines.push("## Warnings");
    lines.push("");
    for (const w of live.warnings) lines.push(`- ${w}`);
    lines.push("");
  }

  return lines.join("\n");
}
