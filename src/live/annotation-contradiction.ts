/**
 * TA-101: the target's own annotations contradict what a probe proved it
 * does.
 *
 * ## What this finding is
 *
 * MCP tool annotations are the tool's claims about the consequences of
 * calling it — `readOnlyHint`, `destructiveHint`, `idempotentHint`,
 * `openWorldHint`. Clients use them to decide how much to ask the user: a
 * tool that declares itself read-only is a candidate for auto-approval, and
 * one that declares a closed world is trusted not to reach an
 * attacker-supplied destination. Nothing enforces any of it. The spec says
 * plainly that a client must not trust these hints from an untrusted
 * server.
 *
 * palar is normally in no position to check them, and says so rather than
 * guessing. There is exactly one situation where it can: a probe whose
 * out-of-band callback arrived. At that moment palar holds both halves of a
 * contradiction — the declaration, read from the server's own
 * `listTools()`, and a demonstration of the opposite, proven by a nonce
 * that came back to a listener the target was never supposed to reach.
 * That pairing, and only that pairing, is this rule.
 *
 * ## The per-kind table, and why it is short
 *
 * CONTRADICTED_BY maps each ProbeKind to the declarations its callback
 * disproves. It is deliberately narrower than "everything that sounds
 * related":
 *
 *   - `command-injection` reaches a shell running an argument palar
 *     supplied. That disproves `readOnlyHint: true` (an arbitrary command
 *     is not a read-only operation), `destructiveHint: false` (an
 *     arbitrary command is not confined to additive updates), and
 *     `openWorldHint: false` (the proof of the injection IS an outbound
 *     request to an address that arrived in the payload).
 *   - `ssrf` fetches a URL palar supplied. That disproves
 *     `openWorldHint: false` and nothing else. It does NOT disprove
 *     `readOnlyHint: true`: a server-side GET may well leave the server's
 *     own environment untouched, so claiming a contradiction there would
 *     be palar inferring rather than reporting, on a rule whose whole
 *     value is that it does not infer.
 *
 * A hint the server never declared is never contradicted. There is no
 * claim to refute, and substituting the spec's default for a missing
 * declaration would produce a finding about something the target never
 * said — see core/annotations.ts on why absence degrades to "not declared"
 * and never to a value.
 *
 * ## Severity: high, not critical
 *
 * The exploitable primitive already carries `critical` under IV-101,
 * escalated from the static hypothesis by the same callback. This is a
 * second, separate defect about the same tool — the declaration that will
 * make a client skip the approval prompt for it — and it is scored as its
 * own thing rather than as more of the first. Stacking a second `critical`
 * would weigh one callback twice.
 *
 * `high` rather than lower because the practical consequence is specific
 * and large: a client honouring these hints converts a gated action into
 * an ungated one. The user is not asked, so the user cannot decline.
 *
 * ## Confidence: confirmed
 *
 * This passes the test core/types.ts sets for that value — "did palar run
 * it and watch it happen?" Both halves are read rather than inferred: the
 * declaration came off the wire in `listTools()`, and the behaviour was
 * proven by a callback bearing this probe's nonce. Note the consequence,
 * which is intended: `confirmedForcesF()` grades any result containing a
 * confirmed finding as F, and compliance.ts's docstring already anticipates
 * exactly this case — a confirmed finding that is not `critical`.
 */
import type { Finding, MCPToolAnnotations } from "../core/types.js";
import {
  ANNOTATION_HINTS,
  describeHint,
  readHint,
  type AnnotationHint,
} from "../core/annotations.js";
import type { ProbeKind } from "./probes.js";
import type { LiveAuditResult, LiveProbeResult } from "./types.js";

export const CONTRADICTION_RULE_ID = "TA-101";

/** The declared value of each hint that a confirmed probe of this kind disproves. */
const CONTRADICTED_BY: Record<ProbeKind, Partial<Record<AnnotationHint, boolean>>> = {
  "command-injection": {
    readOnlyHint: true,
    destructiveHint: false,
    openWorldHint: false,
  },
  ssrf: {
    openWorldHint: false,
  },
};

/** Why each contradicted claim is false, in the reader's terms. */
const REFUTATION: Record<AnnotationHint, string> = {
  readOnlyHint:
    "declared it does not modify its environment, then ran a command palar supplied",
  destructiveHint:
    "declared it performs only additive updates, then ran a command palar supplied " +
    "that was under no such restriction",
  idempotentHint:
    "declared repeated calls have no additional effect, which this probe disproved",
  openWorldHint:
    "declared its domain of interaction is closed, then reached an address that " +
    "arrived in palar's payload",
};

interface Contradiction {
  hint: AnnotationHint;
  declared: boolean;
  probe: LiveProbeResult;
}

/**
 * Every claim on one tool that its own confirmed probes disprove.
 *
 * First confirmation of a given hint wins: a second callback contradicting
 * the same declaration adds no fact the first did not establish.
 */
function contradictionsFor(
  annotations: MCPToolAnnotations | undefined,
  confirmed: LiveProbeResult[]
): Contradiction[] {
  const found = new Map<AnnotationHint, Contradiction>();
  for (const probe of confirmed) {
    for (const [hint, disproved] of Object.entries(CONTRADICTED_BY[probe.kind])) {
      const key = hint as AnnotationHint;
      if (found.has(key)) continue;
      const declared = readHint({ annotations }, key);
      // Undeclared is not contradicted — there is no claim to refute.
      if (declared === undefined || declared !== disproved) continue;
      found.set(key, { hint: key, declared, probe });
    }
  }
  return [...found.values()];
}

function describeCallback(probe: LiveProbeResult): string {
  const at = probe.callback?.receivedAt ?? "unknown time";
  const from = probe.callback?.remoteAddress ?? "unknown address";
  return `nonce ${probe.nonce} received at ${at} from ${from}`;
}

/**
 * One finding per TOOL, not per probe.
 *
 * The defect is a property of the tool's declaration, so two confirmed
 * fields on the same tool are the same false claim demonstrated twice, not
 * two false claims. Emitting one apiece would double its weight in the
 * score for no additional fact.
 */
export function annotationContradictionFindings(
  live: LiveAuditResult,
  file: string
): Finding[] {
  const confirmedByTool = new Map<string, LiveProbeResult[]>();
  for (const probe of live.probes) {
    if (probe.status !== "confirmed") continue;
    const list = confirmedByTool.get(probe.toolName) ?? [];
    list.push(probe);
    confirmedByTool.set(probe.toolName, list);
  }
  if (confirmedByTool.size === 0) return [];

  const annotationsByTool = new Map(live.liveTools.map((t) => [t.name, t.annotations]));

  const findings: Finding[] = [];
  for (const [toolName, confirmed] of confirmedByTool) {
    const annotations = annotationsByTool.get(toolName);
    const contradictions = contradictionsFor(annotations, confirmed);
    if (contradictions.length === 0) continue;

    const claimList = contradictions
      .map((c) => `\`${c.hint}: ${c.declared}\` — the tool ${REFUTATION[c.hint]}`)
      .join("; ");
    const evidence = contradictions
      .map(
        (c) =>
          `${c.hint} by "${toolName}.${c.probe.fieldPath}" ` +
          `(${c.probe.kind}, ${describeCallback(c.probe)})`
      )
      .join("; ");
    // Every hint the tool declared, contradicted or not, so a reader sees
    // the whole claim surface rather than only the failing part — and so an
    // undeclared hint reads as undeclared instead of as its spec default.
    const declaredSurface = ANNOTATION_HINTS.map(
      (hint) => `${hint}: ${describeHint(readHint({ annotations }, hint))}`
    ).join(", ");

    findings.push({
      ruleId: CONTRADICTION_RULE_ID,
      pillar: "schema-integrity",
      severity: "high",
      confidence: "confirmed",
      title: `Tool "${toolName}" declares annotations its own behaviour contradicts`,
      detail:
        `The live server declared ${claimList}. ` +
        `${contradictions.length === 1 ? "That claim is" : "Each of those claims is"} refuted by an ` +
        `out-of-band callback bearing a probe nonce palar generated: ${evidence}. ` +
        `Annotations are what a client reads to decide whether to ask the user before ` +
        `calling a tool, so a false one does not merely misdescribe this tool — it removes ` +
        `the prompt that would have let the user decline. Nothing validates these hints; ` +
        `the spec tells clients not to trust them from an untrusted server, and this is a ` +
        `server that earned that distrust. Full declared surface: ${declaredSurface}.`,
      location: {
        file,
        jsonPath: `tools["${toolName}"].annotations`,
      },
      remediation:
        `Correct the annotations on "${toolName}" so they describe what the tool actually ` +
        `does, and fix the behaviour they were describing — the contradiction is evidence ` +
        `of both a false declaration and a reachable interpreter or outbound request. Do ` +
        `not simply delete the hints: an absent hint falls back to the spec's defaults ` +
        `(readOnlyHint false, destructiveHint true, openWorldHint true), which is the ` +
        `cautious side, but it leaves the underlying defect in place.`,
      complianceRefs: ["OWASP MCP03:2025 - Tool Poisoning"],
    });
  }
  return findings;
}
