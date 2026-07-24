/**
 * Renders the live-scan report, cross-referenced against the static
 * AuditResult for display purposes only — the static Finding[] array
 * itself is never mutated (see types.ts docstring for why).
 *
 * The whole point of this pass: CONFIRMED, ATTEMPTED-UNCONFIRMED, and
 * STATIC-ONLY are kept as visibly separate sections, never flattened back
 * into one undifferentiated finding list.
 */
import type { AuditResult, Finding } from "../core/types.js";
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

function renderProbe(p: LiveProbeResult): string {
  const lines: string[] = [];
  const label = p.status === "confirmed" ? "CONFIRMED" : "ATTEMPTED — UNCONFIRMED";
  lines.push(`#### [${label}] ${p.toolName}.${p.fieldPath} (${p.kind})`);
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
    lines.push(
      `- **Tool call response${call.isError ? " (isError=true)" : ""}:** ${call.textPreview || "(empty)"}`
    );
  }
  if (p.status !== "confirmed") {
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
      "this pass: the injected text targets an LLM's judgment, and mcpguard's live scanner is " +
      "not an LLM, so there is nothing here for it to be tricked into doing. Calling the tool " +
      "directly only exercises the tool's own (non-agentic) code path, captured below."
  );
  const call = check.toolCall;
  if (call && "error" in call) {
    lines.push(`- **Direct tool call:** failed — ${call.error}`);
  } else if (call) {
    lines.push(`- **Direct tool call response:** ${call.textPreview || "(empty)"}`);
  }
  return lines.join("\n");
}

export function renderLiveMarkdownReport(staticResult: AuditResult, live: LiveAuditResult): string {
  const lines: string[] = [];
  lines.push("# mcpguard LIVE audit report");
  lines.push("");
  lines.push(`- **Timestamp:** ${live.timestamp}`);
  lines.push(
    `- **Server:** ${live.serverName} (${live.transportKind}${
      live.pid !== null ? `, pid ${live.pid}` : ""
    })`
  );
  lines.push(`- **Connect time:** ${live.connectDurationMs}ms`);
  lines.push(`- **Live tools discovered:** ${live.liveTools.length}`);
  lines.push(
    `- **Oracle listener:** ${live.oracle.baseUrl} (${
      live.transportKind === "stdio"
        ? "bound to this scan's sandbox network gateway, reachable only from its container"
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
  const unconfirmed = live.probes.filter((p) => p.status === "unconfirmed");

  lines.push("## CONFIRMED — oracle callback received");
  lines.push("");
  lines.push(
    `${confirmed.length} finding(s) proven via real out-of-band callback: the crafted payload ` +
      `was sent to the live tool over a real MCP connection, and something the target did — ` +
      `directly or via a shell command it ran — reached back to mcpguard's local listener.`
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

  if (live.poisoningChecks.length > 0) {
    lines.push("## LIVE-VERIFIED — present on the running server (no oracle equivalent for this class)");
    lines.push("");
    for (const c of live.poisoningChecks) {
      lines.push(renderPoisoning(c));
      lines.push("");
    }
  }

  lines.push("## ATTEMPTED — UNCONFIRMED");
  lines.push("");
  lines.push(
    `${unconfirmed.length} probe(s) sent to the live tool with no callback observed within the ` +
      `timeout. This is NOT the same as "safe" — see each entry's caveat.`
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

  const probedPairs = new Set(live.probes.map((p) => `${p.toolName}::${p.fieldPath}`));
  const poisonedTools = new Set(live.poisoningChecks.map((c) => c.toolName));
  const staticOnly = staticResult.findings.filter((f: Finding) => {
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
      `validation, description hygiene, and non-top-level or non-string-keyword fields).`
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
        "mount, dropped capabilities, resource limits, egress restricted to this scan's own " +
        "oracle). That is container isolation, not a VM or gVisor — a kernel-level container " +
        "escape is not mitigated. See README.md's \"Live scanning\" section for the full list " +
        "of what is and isn't covered."
    );
  } else {
    lines.push(
      "- SSE targets connect to an already-running remote server — there is no local process " +
        "for mcpguard to sandbox here."
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
