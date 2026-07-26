/* One transcript model, two sources.
 *
 * The agent conversation has to read the same whether you are watching it
 * arrive over the WebSocket or opening the job a week later. Those are very
 * different inputs — live `agent_message` events versus the persisted
 * `agent_findings` rows and `negotiation_log` — so both are normalised into
 * `TranscriptMessage[]` here and the panel only ever sees one shape.
 *
 * Doing it this way is what keeps the two views honest: a live run and its
 * replay cannot disagree about who said what, because there is only one
 * renderer and one model. It is the same reasoning as the report exports
 * sharing MarkdownRenderer.
 */

import { verdictLabel } from "@/lib/verdict";
import type { AgentFinding, WSEvent } from "@/types";

export type TranscriptRole =
  | "analyst"
  | "reviser"
  | "negotiator"
  | "judge"
  | "system";

export type TranscriptStatus = "complete" | "no_data" | "failed" | "timeout";

export interface TranscriptClaim {
  claim: string;
  evidence_ref: string;
  confidence: number;
  technique_id: string | null;
}

export interface TranscriptMessage {
  /** Stable identity, used to dedupe replayed events against live ones. */
  id: string;
  speaker: string;
  role: TranscriptRole;
  round: number;
  status: TranscriptStatus;
  text: string;
  confidence?: number;
  claims: TranscriptClaim[];
  dissent: string[];
  ts?: string;
}

const ROLES: TranscriptRole[] = [
  "analyst",
  "reviser",
  "negotiator",
  "judge",
  "system",
];
const STATUSES: TranscriptStatus[] = ["complete", "no_data", "failed", "timeout"];

function asRole(value: unknown): TranscriptRole {
  return ROLES.includes(value as TranscriptRole)
    ? (value as TranscriptRole)
    : "system";
}

function asStatus(value: unknown): TranscriptStatus {
  return STATUSES.includes(value as TranscriptStatus)
    ? (value as TranscriptStatus)
    : "complete";
}

function asClaims(value: unknown): TranscriptClaim[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((raw) => {
    if (!raw || typeof raw !== "object") return [];
    const c = raw as Record<string, unknown>;
    const claim = String(c.claim ?? c.description ?? "").trim();
    if (!claim) return [];
    return [
      {
        claim,
        evidence_ref: String(
          Array.isArray(c.evidence_ref)
            ? c.evidence_ref.join("; ")
            : (c.evidence_ref ?? "")
        ),
        confidence: Number(c.confidence ?? 0),
        technique_id:
          typeof c.technique_id === "string" ? c.technique_id : null,
      },
    ];
  });
}

/**
 * Headline for an analyst message.
 *
 * Mirrors `summarize_claims` in maljan/pipeline/events.py, word for word and
 * deliberately: a live run emits its summary from Python, a replayed run
 * derives it here, and a reader comparing the two must not be able to tell
 * which path produced the line. Change one, change both.
 */
export function summarizeClaims(claims: TranscriptClaim[], layer: string): string {
  if (claims.length === 0) return `${layer}: no claims produced.`;
  // Collapse newlines/markdown whitespace — this is a one-line headline; the
  // expandable claim list shows the value verbatim.
  const lead = claims[0].claim.split(/\s+/).filter(Boolean).join(" ");
  const plural = claims.length === 1 ? "" : "s";
  const headline = `${claims.length} evidence-backed claim${plural} from the ${layer} layer.`;
  if (!lead) return headline;
  return `${headline} Leading: ${lead.length > 240 ? `${lead.slice(0, 239)}…` : lead}`;
}

function asStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((v) => (typeof v === "string" ? v : String((v as { claim?: string })?.claim ?? "")))
    .filter(Boolean);
}

/* ── Live source: WebSocket / replayed stream events ──── */

/**
 * Build the transcript from pipeline events.
 *
 * Accepts the raw event list the Live tab already holds (WS plus the
 * `/jobs/{id}/events` back-fill), so no second subscription is needed.
 * Non-`agent_message` events are ignored — they drive the status header, not
 * the conversation.
 */
export function messagesFromEvents(events: WSEvent[]): TranscriptMessage[] {
  const out: TranscriptMessage[] = [];
  const seen = new Set<string>();

  for (const event of events) {
    if (event.type !== "agent_message") continue;
    const d = (event.data ?? {}) as Record<string, unknown>;
    const speaker = String(d.speaker ?? "unknown");
    const role = asRole(d.role);
    const round = Number(d.round ?? 0);
    const text = String(d.text ?? "").trim();

    // The stream back-fill and the live socket overlap by design, so the same
    // message can arrive twice. Identity is (speaker, role, round) — a given
    // agent speaks once per role per round.
    const id = `${role}:${speaker}:${round}`;
    if (seen.has(id)) continue;
    seen.add(id);

    out.push({
      id,
      speaker,
      role,
      round,
      status: asStatus(d.status),
      text,
      confidence: d.confidence === undefined ? undefined : Number(d.confidence),
      claims: asClaims(d.claims),
      dissent: asStrings(d.dissent),
      ts: event.ts,
    });
  }
  return sortTranscript(out);
}

/* ── Persisted source: the stored report ─────────────── */

interface NegotiationEntry {
  round?: number;
  agent?: string;
  argument?: string;
  confidence?: number;
}

/**
 * Rebuild the transcript from what was saved.
 *
 * Runs that finished before the live feed existed still have their findings
 * and negotiation log, so their conversation is reconstructed rather than
 * shown as empty — the panel is useful on every historical job, not only on
 * new ones.
 */
export function messagesFromReport(
  findings: AgentFinding[] | null | undefined,
  negotiationLog: Record<string, unknown> | null | undefined,
  verdict?: string | null
): TranscriptMessage[] {
  const out: TranscriptMessage[] = [];

  for (const f of findings ?? []) {
    // revision_rounds > 0 means the persisted row is the agent's *final*
    // position after revising, not its opening one. Label it truthfully;
    // the per-round intermediate ISRs are not persisted.
    const revised = (f.revision_rounds ?? 0) > 0;
    out.push({
      id: `analyst:${f.agent_name}:0`,
      speaker: f.agent_name,
      role: revised ? "reviser" : "analyst",
      round: revised ? f.revision_rounds : 0,
      status: (f.status ?? "complete") as TranscriptStatus,
      text: f.status_reason || summarizeClaims(asClaims(f.claims), f.domain),
      confidence: f.final_confidence,
      claims: asClaims(f.claims),
      dissent: asStrings(f.dissent_items),
    });
  }

  const history = (negotiationLog?.discussion_history ?? []) as NegotiationEntry[];
  if (Array.isArray(history)) {
    for (const entry of history) {
      const speaker = String(entry.agent ?? "Mediator");
      const round = Number(entry.round ?? 0);
      const text = String(entry.argument ?? "").trim();
      if (!text) continue;
      out.push({
        id: `negotiator:${speaker}:${round}`,
        speaker,
        role: "negotiator",
        round,
        status: text.startsWith("[ERROR]") ? "failed" : "complete",
        text,
        // Stored as 0-100 by the worker; the model is 0-1 throughout.
        confidence: entry.confidence === undefined ? undefined : Number(entry.confidence) / 100,
        claims: [],
        dissent: [],
      });
    }
  }

  if (verdict) {
    const consensus = negotiationLog?.is_consensus === true;
    out.push({
      id: "judge:Judge:final",
      speaker: "Judge",
      role: "judge",
      round: Number(negotiationLog?.iteration_count ?? 0),
      status: "complete",
      // audit 2026-07-26 (T2): the backend spells this "Malware"; every user-
      // facing surface says "Malicious". Normalise here or the transcript
      // contradicts the header two inches above it.
      text: `Final verdict: ${verdictLabel(verdict)}.${
        consensus
          ? " Analysts reached consensus."
          : " Closed without full consensus — see the mediator rounds above."
      }`,
      claims: [],
      dissent: [],
    });
  }

  return sortTranscript(out);
}

/* ── Ordering ────────────────────────────────────────── */

// Within a round the pipeline always runs in this order, and the transcript
// must read that way even when events arrive out of order or a replayed batch
// is concatenated with live ones.
const ROLE_ORDER: Record<TranscriptRole, number> = {
  analyst: 0,
  reviser: 1,
  negotiator: 2,
  system: 3,
  judge: 4,
};

export function sortTranscript(messages: TranscriptMessage[]): TranscriptMessage[] {
  return [...messages].sort((a, b) => {
    // The judge speaks last, whatever round counter it carries.
    if (a.role === "judge" !== (b.role === "judge")) {
      return a.role === "judge" ? 1 : -1;
    }
    if (a.round !== b.round) return a.round - b.round;
    return ROLE_ORDER[a.role] - ROLE_ORDER[b.role];
  });
}

/** True when the speaker is a pipeline stage rather than a domain analyst. */
export function isStageSpeaker(role: TranscriptRole): boolean {
  return role === "negotiator" || role === "judge" || role === "system";
}
