/* One transcript model, three sources.
 *
 * The agent conversation has to read the same whether you are watching it
 * arrive over the WebSocket or opening the job a month later, so every input is
 * normalised into `TranscriptMessage[]` here and the panel only ever sees one
 * shape:
 *
 *  - `messagesFromEvents`     — the live WebSocket feed and its stream back-fill.
 *  - `messagesFromTranscript` — the recorded `agent_messages` rows. Not a
 *    reconstruction: the worker writes down each event as it broadcasts it, so
 *    these are the same messages the live viewer saw.
 *  - `messagesFromReport`     — a lossy rebuild from `agent_findings` and
 *    `negotiation_log`, for reports written before the recording existed.
 *
 * One renderer and one model is what keeps the views honest — a live run and
 * its replay cannot disagree about who said what.
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
  /** The skimmable one-line body. */
  text: string;
  /**
   * The speaker's full prose report for this round, when it wrote one.
   *
   * Deliberately separate from `text`: putting the prose in the body was tried
   * and undone once, because it restated every claim inline and turned the
   * conversation into a wall. The panel keeps `text` as the message and puts
   * this behind a disclosure.
   */
  report?: string;
  /** True when `report` was cut at the producer's size cap. */
  reportTruncated?: boolean;
  confidence?: number;
  claims: TranscriptClaim[];
  dissent: string[];
  ts?: string;
  /** Emission order within the run. Only present on persisted rows. */
  seq?: number;
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
      report: typeof d.report === "string" && d.report ? d.report : undefined,
      reportTruncated: d.report_truncated === true || undefined,
      confidence: d.confidence === undefined ? undefined : Number(d.confidence),
      claims: asClaims(d.claims),
      dissent: asStrings(d.dissent),
      ts: event.ts,
    });
  }
  return sortTranscript(out);
}

/* ── Persisted source: the recorded transcript ───────── */

/** One `agent_messages` row, as returned by the API. */
export interface TranscriptRow {
  seq: number;
  speaker: string;
  role: string;
  round: number;
  status: string;
  text: string;
  report?: string | null;
  report_truncated?: boolean;
  confidence?: number | null;
  claims?: unknown;
  dissent?: unknown;
  ts?: string | null;
}

/**
 * Map the recorded conversation straight onto the model.
 *
 * This is the preferred replay path and it does no reconstruction at all: the
 * worker writes down every `agent_message` as it broadcasts it, so these rows
 * *are* the live feed, stored. A run read a month later shows the same
 * messages, in the same order, that its live viewer saw — including the
 * per-round revisions and the sycophancy intervention, neither of which
 * survives anywhere else.
 *
 * `messagesFromReport` below remains for reports written before the recording
 * existed.
 */
export function messagesFromTranscript(
  rows: TranscriptRow[] | null | undefined
): TranscriptMessage[] {
  const out: TranscriptMessage[] = [];
  for (const row of rows ?? []) {
    const role = asRole(row.role);
    const speaker = String(row.speaker ?? "unknown");
    const round = Number(row.round ?? 0);
    out.push({
      id: `${role}:${speaker}:${round}`,
      speaker,
      role,
      round,
      status: asStatus(row.status),
      text: String(row.text ?? ""),
      report: row.report || undefined,
      reportTruncated: row.report_truncated === true || undefined,
      confidence:
        row.confidence === null || row.confidence === undefined
          ? undefined
          : Number(row.confidence),
      claims: asClaims(row.claims),
      dissent: asStrings(row.dissent),
      ts: row.ts || undefined,
      seq: Number(row.seq ?? 0),
    });
  }
  return sortTranscript(out);
}

/* ── Legacy source: rebuilt from the stored report ───── */

interface NegotiationEntry {
  round?: number;
  agent?: string;
  argument?: string;
  confidence?: number;
}

/**
 * Rebuild an approximate transcript from the summary tables.
 *
 * The fallback for reports written before `agent_messages` existed. It is
 * genuinely lossy and cannot be otherwise — the source data is gone:
 * `agent_findings` holds one row per agent (its *final* ISR, not its position
 * in each round), and the sycophancy intervention was never persisted at all.
 * What can be recovered is recovered: final positions, every mediator round,
 * and a synthesised verdict line, so an old job still reads as a conversation
 * instead of showing empty.
 *
 * Prefer `messagesFromTranscript` whenever the report carries one.
 */
export function messagesFromReport(
  findings: AgentFinding[] | null | undefined,
  negotiationLog: Record<string, unknown> | null | undefined,
  verdict?: string | null
): TranscriptMessage[] {
  const out: TranscriptMessage[] = [];

  for (const f of findings ?? []) {
    // revision_rounds > 0 means this row is the agent's *final* position
    // after revising, not its opening one. Label it truthfully; for these
    // legacy reports the per-round ISRs were never written down.
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

/**
 * Combine the persisted transcript with the live one, persisted winning.
 *
 * Both sources are valid at different points in a job's life and neither
 * covers all of it: a *running* job has events and no report row at all, a job
 * older than the event stream's 24 h TTL has the report and no events, and in
 * between both exist. Rendering only one of them left the PROCESS tab claiming
 * "no agent findings" for the entire duration of every analysis.
 *
 * Persisted messages take precedence on conflict because they are the record —
 * they carry the final revision round and the stored status. Identity is the
 * shared `role:speaker:round` key, so the same message from both sources
 * collapses to one.
 */
export function mergeTranscripts(
  persisted: TranscriptMessage[],
  live: TranscriptMessage[]
): TranscriptMessage[] {
  const byId = new Map<string, TranscriptMessage>();
  for (const message of live) byId.set(message.id, message);
  for (const message of persisted) {
    const existing = byId.get(message.id);
    if (!existing) {
      byId.set(message.id, message);
      continue;
    }
    /* Field-level, not wholesale. Replacing the object meant a persisted row
     * missing a field would *erase* the live one that had it — the legacy
     * rebuild carries no prose report, so on a job with both sources the
     * report a live viewer could read would vanish the moment the run
     * finished. Persisted still wins wherever it actually has a value. */
    byId.set(message.id, {
      ...existing,
      ...Object.fromEntries(
        Object.entries(message).filter(([, v]) => v !== undefined)
      ),
    } as TranscriptMessage);
  }
  return sortTranscript([...byId.values()]);
}

export function sortTranscript(messages: TranscriptMessage[]): TranscriptMessage[] {
  return [...messages].sort((a, b) => {
    // Recorded emission order beats every heuristic below, and is the only
    // thing that can separate two speakers inside one round. Present only on
    // rows that came from the recording, so the fallbacks still matter.
    if (a.seq !== undefined && b.seq !== undefined && a.seq !== b.seq) {
      return a.seq - b.seq;
    }
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
