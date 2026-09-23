/* ── Pipeline events ──────────────────────────────────────
 *
 * The wire format of the live conversation, mirroring
 * `src/maljan/pipeline/events.py` and the publisher in
 * `apps/api/app/worker/analysis_worker.py` field for field. Types only: the
 * view that draws them is M4's.
 *
 * Every event a run publishes carries `seq` in its `data` — a monotonic,
 * gap-free number per job, assigned by the publisher and by nothing else. It
 * is the ordering key, the dedupe identity and the cursor a client resumes
 * from (`?since=` on the socket and on `GET /jobs/{id}/events`). It is
 * optional here because a run recorded before sequencing existed still
 * replays, and a `heartbeat` is not part of the feed at all.
 */

export type WSEventType =
  | "status_change"
  | "pipeline_started"
  | "agent_progress"
  /* One transcript line from a pipeline node — an analyst's findings, a
   * mediator's ruling, a revision, the judge's verdict. Carries a ``role``
   * discriminator rather than one event type per speaker, so a new
   * participant needs no client change. See maljan/pipeline/events.py. */
  | "agent_message"
  /* Part of what an agent is saying, before it has finished saying it. One
   * model turn's text as the loop produces it, not a token; published only
   * when `core.events.stream_deltas` is on. */
  | "agent_message_delta"
  | "phase_change"
  /* One stage of the team announcing itself, exactly once each: `started`
   * from its first node, `skipped` instead when its condition is false, and
   * `finished` from the one node that runs after everything in it is done.
   * See maljan/pipeline/nodes.py. */
  | "stage_started"
  | "stage_skipped"
  | "stage_finished"
  /* Everyone who can speak in this run and the stages they speak in, once,
   * before anybody does. The same shape the job endpoint carries, so a run
   * opened after the fact is named the same way a live one is. */
  | "roster"
  /* One tool call as it starts and as it answers. The finish carries the
   * evidence-ledger id its full result is filed under. */
  | "tool_call_started"
  | "tool_call_finished"
  /* One correction a producer was shown before it answered again. */
  | "validation_feedback"
  /* A question the judge asked mid-loop, rather than its closing verdict. */
  | "judge_question"
  /* The budget meter: one agent's steps and seconds against its caps every
   * few steps and at the end of its loop, and the cap that ended a stage's
   * work when a cap did. See maljan/pipeline/events.py. */
  | "budget_tick"
  | "stage_ended_at_cap"
  /* A tool server this job stopped calling for a while after a run of
   * calls it did not answer. See maljan/providers/server_guard.py. */
  | "tool_server_rested"
  /* An agent's model list moved on to its next model because the one before
   * failed as a provider; once per switch, whether or not deltas stream. */
  | "model_fallback"
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
  /** Present on an event the Redis stream answered; absent from one the
   *  `job_events` table replayed. `seq` is the ordering key, not this. */
  stream_id?: string;
}

/** What an `agent_message` *is*. The console switches on it: a tool call is
 *  not a line somebody said, and a delegated ask is drawn as an arrow between
 *  two participants rather than as a line to the room. `says` is the default
 *  and is what every message published before the field existed was. */
export type AgentMessageKind =
  | "says"
  | "tool_call"
  | "tool_result"
  | "validation_feedback"
  | "judge_question"
  | "verdict"
  | "system"
  | "delegation_ask"
  | "delegation_answer";

export interface AgentMessageEventData {
  speaker: string;
  role: string;
  round: number;
  status: string;
  text: string;
  kind: AgentMessageKind;
  /** The stage the speaker was working in, when the producer knew it. */
  stage?: string;
  /** The agent this line was said *to*, when it was said to one agent rather
   *  than to the room. Absent on every other line. */
  addressed_to?: string | null;
  /** The speaker's configured label, so a reader who cannot open the admin
   *  settings sees a name rather than a registry key. */
  display_name?: string;
  confidence?: number;
  claims?: unknown[];
  dissent?: string[];
  report?: string;
  report_truncated?: boolean;
  seq?: number;
  /* A `tool_call` / `tool_result` line. No producer emits either kind today —
   * `emit_agent_message` calls them an extension point — and the conversation
   * view already reads these five and falls back on every one. Declared so
   * the shape the view reads is a shape something describes. */
  tool?: string;
  server?: string;
  evidence_id?: string;
  ok?: boolean;
  duration_ms?: number;
}

export interface AgentMessageDeltaEventData {
  stage: string;
  agent: string;
  /** Empty on a turn that only asked for tools, published for its tokens. */
  text_delta: string;
  /** The model that gave this turn, as `provider/model`. */
  model?: string;
  /** What the turn spent as the provider reported it; absent where it
   *  reported nothing. */
  tokens?: { input_tokens: number; output_tokens: number; cost?: number };
  seq?: number;
}

export interface ModelFallbackEventData {
  stage: string;
  agent: string;
  /** The model that answers from here on, as `provider/model`. */
  model: string;
  /** Why, in words: the failure of each model before it. */
  reason: string;
  seq?: number;
}

export interface ToolServerRestedEventData {
  server: string;
  failures: number;
  cooldown_s: number;
  reason: string;
  seq?: number;
}

export interface ToolCallStartedEventData {
  stage: string;
  agent: string;
  tool: string;
  /** The tool server the tool came from; `null` for an in-process tool. */
  server: string | null;
  /** A short, redacted line — never the arguments as sent. The arguments are
   *  on the ledger entry, behind the same ownership check as the report. */
  args_summary: string;
  seq?: number;
}

export interface ToolCallFinishedEventData {
  stage: string;
  agent: string;
  tool: string;
  server: string | null;
  /** The ledger id the full result is filed under, e.g. `ev_0007`. */
  evidence_id: string;
  ok: boolean;
  duration_ms: number;
  /** A capped headline. A failed call says what would fix it, not what broke. */
  summary: string;
  seq?: number;
}

export interface ValidationFeedbackEventData {
  stage: string;
  agent: string;
  code: string;
  message: string;
  /** Which correction turn this was: 1 for the first. */
  retry_index: number;
  seq?: number;
}

export interface JudgeQuestionEventData {
  stage: string;
  text: string;
  addressed_to: string | null;
  seq?: number;
}

export interface RosterAgent {
  key: string;
  label: string;
  role: string;
  /** The stages this agent speaks in. Empty for a specialist that no stage
   *  names — one a lead reaches through its `ask_<key>` tools. */
  stages: string[];
  /** The agents that can task this one, when no stage names it. Absent on an
   *  agent a stage names: nothing had to ask it to be there. */
  via?: string[];
}

export interface RosterStage {
  key: string;
  label: string;
  kind: string;
  agents: string[];
}

export interface RosterEventData {
  agents: RosterAgent[];
  stages: RosterStage[];
  seq?: number;
}

/** The roster as the job endpoint carries it, which is the same shape without
 *  the publisher's sequence number. */
export type JobRoster = Pick<RosterEventData, "agents" | "stages">;
