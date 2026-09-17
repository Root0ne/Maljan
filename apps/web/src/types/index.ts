/* ── API / Domain Types ─────────────────────────────────
 *
 * This module used to mirror most of the API
 * surface, but the pages consume the DTOs exported from ``@/lib/api`` and the
 * rich payload types from ``@/types/malware-report`` instead. Only the four
 * types below are actually imported anywhere; the rest were removed so this
 * file stops looking like a second, stale source of truth.
 */

export type AgentFindingStatus =
  | "complete"
  | "no_data"
  | "no_claims"
  | "failed"
  | "timeout";

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

/* The event wire format lives in `./events`, beside the payload shape of each
 * type. Re-exported here because every consumer imports it from `@/types` and
 * one spelling of an event type is the point. */
export * from "./events";
