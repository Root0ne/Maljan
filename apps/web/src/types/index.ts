/* ── API / Domain Types ─────────────────────────────────
 *
 * audit 2026-07-26 (§5 "ölü kod"): this module used to mirror most of the API
 * surface, but the pages consume the DTOs exported from ``@/lib/api`` and the
 * rich payload types from ``@/types/malware-report`` instead. Only the four
 * types below are actually imported anywhere; the rest were removed so this
 * file stops looking like a second, stale source of truth.
 */

export type AgentFindingStatus = "complete" | "no_data" | "failed" | "timeout";

export interface AgentFinding {
  agent_name: string;
  domain: string;
  claims: unknown[] | null;
  dissent_items: unknown[] | null;
  revision_rounds: number;
  final_confidence: number;
  /* D15+D16: lifecycle status separate from confidence. Legacy rows
   * persisted before the field existed default to ``"complete"`` server-
   * side so this is non-optional on the wire. */
  status: AgentFindingStatus;
  status_reason?: string | null;
}

/* ── WebSocket Events ────────────────────────────────── */
export type WSEventType =
  | "status_change"
  | "pipeline_started"
  | "agent_progress"
  /* One transcript line from a pipeline node — an analyst's findings, a
   * mediator's ruling, a revision, the judge's verdict. Carries a ``role``
   * discriminator rather than one event type per speaker, so a new
   * participant needs no client change. See maljan/pipeline/events.py. */
  | "agent_message"
  | "phase_change"
  | "completed"
  | "enrichment_complete"
  | "error"
  | "cancelled"
  | "heartbeat"
  | "pong";

export interface WSEvent {
  type: WSEventType;
  data: Record<string, unknown>;
  ts: string;
}
