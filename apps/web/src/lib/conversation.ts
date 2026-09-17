/* The run, read as a conversation.
 *
 * One pure function turns the event feed the store holds into what the
 * Conversation view draws: the participants, and the exchange grouped by
 * stage and by round. Everything the view needs to decide is decided here —
 * which speaker a line belongs to, what kind of act it is, which tool call a
 * result closes, what an agent is doing right now — so the components stay
 * presentation and the rules stay testable.
 *
 * Three shapes of input fold into one model. Events published by a running
 * pipeline; the same events replayed from the recording; and the stored
 * `agent_messages` rows of a run whose feed predates the recording, which the
 * store turns into events before they arrive here. A run recorded before the
 * publisher numbered its events keeps the order it arrived in, and nothing
 * here requires a number to exist.
 */

import type { RunEvent } from "@/lib/runStore";
import type { JobRoster } from "@/types";

/* ── Model ─────────────────────────────────────────────── */

/** One evidence-backed claim, as a speaker attached it to a line. */
export interface TranscriptClaim {
  claim: string;
  evidence_ref: string;
  confidence: number;
  technique_id: string | null;
}

/** One `agent_messages` row, as the report endpoint returns it. */
export interface TranscriptRow {
  /** The number the publisher gave this message. `null` for a run recorded
   *  before the publisher numbered anything. */
  seq?: number | null;
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
  addressed_to?: string | null;
  stage?: string | null;
}

/** What one line in the conversation is. Mirrors the publisher's message
 *  kinds, with the two halves of a tool call drawn as the single row they
 *  are. */
export type ItemKind =
  | "says"
  | "verdict"
  | "system"
  | "judge_question"
  | "delegation_ask"
  | "delegation_answer"
  | "validation_feedback"
  | "tool_call";

/** The three things a reader filters by: speech, machine work, and the notes
 *  the room makes about both. */
export type ItemGroup = "says" | "tools" | "notices";

export interface ToolDetail {
  name: string;
  server: string | null;
  /** The ledger id the full result is filed under; empty while it runs. */
  evidenceId: string;
  /** `null` while the call is still running. */
  ok: boolean | null;
  durationMs: number;
  summary: string;
}

export interface ConversationItem {
  id: string;
  kind: ItemKind;
  stage: string;
  round: number;
  /** The agent key, which is what everything joins on. Empty for a line the
   *  room said rather than a participant. */
  speaker: string;
  /** The name a reader sees: the label an operator gave the agent. */
  displayName: string;
  addressedTo?: string;
  addressedToName?: string;
  text: string;
  ts: string;
  seq?: number;
  status?: string;
  confidence?: number;
  claims: TranscriptClaim[];
  dissent: string[];
  report?: string;
  reportTruncated?: boolean;
  /** True while the speaker is still producing this line. */
  streaming?: boolean;
  tool?: ToolDetail;
  /** The validator's code, on a correction. */
  code?: string;
  retryIndex?: number;
}

export interface ConversationRound {
  round: number;
  items: ConversationItem[];
}

export type StageState = "running" | "done" | "skipped" | "pending";

export interface ConversationStage {
  key: string;
  label: string;
  kind: string;
  state: StageState;
  /** Why the stage declined. Empty unless it was skipped. */
  reason: string;
  durationMs: number;
  rounds: ConversationRound[];
}

export type ParticipantState = "waiting" | "working" | "done";

export interface Participant {
  key: string;
  name: string;
  role: string;
  /** The stages this agent speaks in. Empty for a specialist a lead reaches. */
  stages: string[];
  /** The agents that can task this one, when no stage names it. */
  via: string[];
  state: ParticipantState;
  messages: number;
  toolCalls: number;
}

export interface Conversation {
  participants: Participant[];
  stages: ConversationStage[];
}

/* ── Normalising ───────────────────────────────────────── */

export function normalizeClaims(value: unknown): TranscriptClaim[] {
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
          Array.isArray(c.evidence_ref) ? c.evidence_ref.join("; ") : (c.evidence_ref ?? ""),
        ),
        confidence: Number(c.confidence ?? 0),
        technique_id: typeof c.technique_id === "string" ? c.technique_id : null,
      },
    ];
  });
}

export function normalizeDissent(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((v) => (typeof v === "string" ? v : String((v as { claim?: string })?.claim ?? "")))
    .filter(Boolean);
}

const MESSAGE_KINDS: ItemKind[] = [
  "says",
  "verdict",
  "system",
  "judge_question",
  "delegation_ask",
  "delegation_answer",
  "validation_feedback",
  "tool_call",
];

/** What an `agent_message` is. `says` is the default and is what every
 *  message published before the field existed was; `tool_result` is drawn as
 *  the tool row its `tool_call` opened. */
function kindOf(value: unknown): ItemKind {
  if (value === "tool_result") return "tool_call";
  return MESSAGE_KINDS.includes(value as ItemKind) ? (value as ItemKind) : "says";
}

export function groupOf(kind: ItemKind): ItemGroup {
  if (kind === "tool_call") return "tools";
  if (kind === "validation_feedback" || kind === "system") return "notices";
  return "says";
}

/**
 * A registry key made readable, for a speaker no roster names.
 *
 * Only a key is rewritten. A speaker that already reads as a name — anything
 * carrying a capital or a space, which is how the pipeline's own
 * "Sycophancy detector" and "Mediator" arrive — is left exactly as it was
 * written: re-casing somebody's name is not a formatting improvement.
 */
export function prettyName(key: string): string {
  const trimmed = key.trim();
  if (!trimmed) return "Unknown";
  if (/[A-Z\s]/.test(trimmed)) return trimmed;
  return trimmed.replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/* ── Building ──────────────────────────────────────────── */

interface StageDraft {
  key: string;
  label: string;
  kind: string;
  state: StageState;
  reason: string;
  durationMs: number;
  items: ConversationItem[];
  round: number;
}

export function buildConversation(
  events: readonly RunEvent[],
  roster: JobRoster | null,
): Conversation {
  const stages = new Map<string, StageDraft>();
  const order: string[] = [];
  const names = new Map<string, string>();
  const seenSpeakers = new Map<string, Participant>();
  /* One open bubble per speaker and stage, which is where deltas land until
   * the message that closes the turn replaces them. */
  const streaming = new Map<string, ConversationItem>();
  /* Started calls waiting for their result, oldest first per agent and tool. */
  const pending = new Map<string, ConversationItem[]>();

  for (const stage of roster?.stages ?? []) {
    names.set(`stage:${stage.key}`, stage.label || stage.key);
  }
  for (const agent of roster?.agents ?? []) {
    names.set(agent.key, agent.label || prettyName(agent.key));
    seenSpeakers.set(agent.key, {
      key: agent.key,
      name: agent.label || prettyName(agent.key),
      role: agent.role,
      stages: agent.stages ?? [],
      via: agent.via ?? [],
      state: "waiting",
      messages: 0,
      toolCalls: 0,
    });
  }

  function nameOf(key: string, given?: string): string {
    if (given) {
      names.set(key, given);
      return given;
    }
    return names.get(key) ?? prettyName(key);
  }

  function participant(key: string, given?: string): Participant | null {
    if (!key) return null;
    const existing = seenSpeakers.get(key);
    if (existing) {
      if (given) existing.name = given;
      return existing;
    }
    const created: Participant = {
      key,
      name: nameOf(key, given),
      role: "",
      stages: [],
      via: [],
      state: "waiting",
      messages: 0,
      toolCalls: 0,
    };
    seenSpeakers.set(key, created);
    return created;
  }

  function draft(key: string): StageDraft {
    const existing = stages.get(key);
    if (existing) return existing;
    const created: StageDraft = {
      key,
      label: names.get(`stage:${key}`) ?? (key ? prettyName(key) : ""),
      kind: "",
      state: key ? "pending" : "running",
      reason: "",
      durationMs: 0,
      items: [],
      round: 0,
    };
    stages.set(key, created);
    order.push(key);
    return created;
  }

  let index = 0;
  for (const event of events) {
    index += 1;
    const data = event.data ?? {};
    const stageKey = text(data.stage);
    const id = event.seq !== undefined ? `seq:${event.seq}` : `n:${index}`;

    if (event.type === "stage_started" || event.type === "stage_skipped" || event.type === "stage_finished") {
      const stage = draft(text(data.stage));
      stage.kind = text(data.kind) || stage.kind;
      if (event.type === "stage_started") stage.state = "running";
      if (event.type === "stage_skipped") {
        stage.state = "skipped";
        stage.reason = text(data.reason) || "did not run";
      }
      if (event.type === "stage_finished") {
        stage.state = "done";
        stage.durationMs = Number(data.duration_ms ?? stage.durationMs) || 0;
      }
      continue;
    }

    if (event.type === "agent_progress") {
      const who = participant(text(data.agent));
      const phase = text(data.phase);
      if (who) {
        if (phase === "done") who.state = "done";
        else if (phase === "analyzing") who.state = "working";
        else who.state = "waiting";
      }
      continue;
    }

    if (event.type === "agent_message_delta") {
      const speaker = text(data.agent);
      if (!speaker) continue;
      const stage = draft(stageKey);
      const who = participant(speaker);
      if (who) who.state = "working";
      const openKey = `${stageKey}|${speaker}`;
      const open = streaming.get(openKey);
      if (open) {
        open.text += text(data.text_delta);
        continue;
      }
      const item: ConversationItem = {
        id,
        kind: "says",
        stage: stageKey,
        round: stage.round,
        speaker,
        displayName: nameOf(speaker),
        text: text(data.text_delta),
        ts: event.ts,
        seq: event.seq,
        claims: [],
        dissent: [],
        streaming: true,
      };
      streaming.set(openKey, item);
      stage.items.push(item);
      continue;
    }

    if (event.type === "agent_message") {
      const speaker = text(data.speaker);
      const stage = draft(stageKey);
      const round = Number(data.round ?? 0) || 0;
      stage.round = round;
      const kind = kindOf(data.kind);
      const openKey = `${stageKey}|${speaker}`;
      const open = streaming.get(openKey);
      if (open) {
        /* The finished message replaces what was streamed: the publisher sends
         * the whole line once the turn closes, and keeping both would show it
         * twice. */
        stage.items.splice(stage.items.indexOf(open), 1);
        streaming.delete(openKey);
      }
      const who = participant(speaker, text(data.display_name) || undefined);
      if (who) {
        who.messages += 1;
        who.state = "done";
      }
      const addressedTo = text(data.addressed_to) || undefined;
      stage.items.push({
        id,
        kind,
        stage: stageKey,
        round,
        speaker,
        displayName: nameOf(speaker, text(data.display_name) || undefined),
        addressedTo,
        addressedToName: addressedTo ? nameOf(addressedTo) : undefined,
        text: text(data.text),
        ts: event.ts,
        seq: event.seq,
        status: text(data.status) || undefined,
        confidence: data.confidence === undefined ? undefined : Number(data.confidence),
        claims: normalizeClaims(data.claims),
        dissent: normalizeDissent(data.dissent),
        report: text(data.report) || undefined,
        reportTruncated: data.report_truncated === true || undefined,
        ...(kind === "tool_call"
          ? {
              tool: {
                name: text(data.tool) || text(data.text),
                server: text(data.server) || null,
                evidenceId: text(data.evidence_id),
                ok: null,
                durationMs: 0,
                summary: text(data.text),
              },
            }
          : {}),
      });
      continue;
    }

    if (event.type === "tool_call_started") {
      const speaker = text(data.agent);
      const stage = draft(stageKey);
      const who = participant(speaker);
      if (who) who.state = "working";
      const item: ConversationItem = {
        id,
        kind: "tool_call",
        stage: stageKey,
        round: stage.round,
        speaker,
        displayName: nameOf(speaker),
        text: text(data.args_summary),
        ts: event.ts,
        seq: event.seq,
        claims: [],
        dissent: [],
        tool: {
          name: text(data.tool),
          server: text(data.server) || null,
          evidenceId: "",
          ok: null,
          durationMs: 0,
          summary: text(data.args_summary),
        },
      };
      stage.items.push(item);
      const key = `${stageKey}|${speaker}|${text(data.tool)}`;
      const queue = pending.get(key) ?? [];
      queue.push(item);
      pending.set(key, queue);
      continue;
    }

    if (event.type === "tool_call_finished") {
      const speaker = text(data.agent);
      const stage = draft(stageKey);
      const who = participant(speaker);
      if (who) who.toolCalls += 1;
      const key = `${stageKey}|${speaker}|${text(data.tool)}`;
      const queue = pending.get(key) ?? [];
      const started = queue.shift();
      pending.set(key, queue);
      const detail: ToolDetail = {
        name: text(data.tool),
        server: text(data.server) || null,
        evidenceId: text(data.evidence_id),
        ok: data.ok !== false,
        durationMs: Number(data.duration_ms ?? 0) || 0,
        summary: text(data.summary),
      };
      if (started) {
        started.tool = detail;
        started.text = detail.summary || started.text;
        continue;
      }
      stage.items.push({
        id,
        kind: "tool_call",
        stage: stageKey,
        round: stage.round,
        speaker,
        displayName: nameOf(speaker),
        text: detail.summary,
        ts: event.ts,
        seq: event.seq,
        claims: [],
        dissent: [],
        tool: detail,
      });
      continue;
    }

    if (event.type === "validation_feedback") {
      const speaker = text(data.agent);
      const stage = draft(stageKey);
      stage.items.push({
        id,
        kind: "validation_feedback",
        stage: stageKey,
        round: stage.round,
        speaker,
        displayName: nameOf(speaker),
        text: text(data.message),
        ts: event.ts,
        seq: event.seq,
        claims: [],
        dissent: [],
        code: text(data.code),
        retryIndex: Number(data.retry_index ?? 0) || 0,
      });
      continue;
    }

    if (event.type === "judge_question") {
      const stage = draft(stageKey);
      const addressedTo = text(data.addressed_to) || undefined;
      stage.items.push({
        id,
        kind: "judge_question",
        stage: stageKey,
        round: stage.round,
        speaker: "judge",
        displayName: nameOf("judge"),
        addressedTo,
        addressedToName: addressedTo ? nameOf(addressedTo) : undefined,
        text: text(data.text),
        ts: event.ts,
        seq: event.seq,
        claims: [],
        dissent: [],
      });
      continue;
    }

    if (event.type === "stage_ended_at_cap") {
      const stage = draft(stageKey);
      const agent = text(data.agent);
      stage.items.push({
        id,
        kind: "system",
        stage: stageKey,
        round: stage.round,
        speaker: "",
        displayName: "",
        text: `${nameOf(agent)} stopped on its ${text(data.cap)} cap${
          text(data.detail) ? ` — ${text(data.detail)}` : ""
        }.`,
        ts: event.ts,
        seq: event.seq,
        claims: [],
        dissent: [],
      });
      continue;
    }
  }

  return {
    participants: [...seenSpeakers.values()],
    stages: order.map((key) => {
      const stage = stages.get(key) as StageDraft;
      return {
        key: stage.key,
        label: stage.label,
        kind: stage.kind,
        state: stage.state,
        reason: stage.reason,
        durationMs: stage.durationMs,
        rounds: intoRounds(stage.items),
      };
    }),
  };
}

/** Consecutive items of one round, in the order they happened. A round is a
 *  moment in the argument, so it marks time rather than sorting it. */
function intoRounds(items: ConversationItem[]): ConversationRound[] {
  const rounds: ConversationRound[] = [];
  for (const item of items) {
    const last = rounds[rounds.length - 1];
    if (last && last.round === item.round) last.items.push(item);
    else rounds.push({ round: item.round, items: [item] });
  }
  return rounds;
}

/* ── Filtering ─────────────────────────────────────────── */

export interface ConversationFilter {
  /** Agent keys to keep. Empty keeps everyone. */
  agents: ReadonlySet<string>;
  /** Groups to keep. Empty keeps everything. */
  groups: ReadonlySet<ItemGroup>;
}

/** The conversation as a filter leaves it. A stage with nothing left to show
 *  is dropped, so a filter never leaves a header standing over an empty room. */
export function filterConversation(
  stages: readonly ConversationStage[],
  filter: ConversationFilter,
): ConversationStage[] {
  const all = filter.agents.size === 0 && filter.groups.size === 0;
  if (all) return [...stages];
  const out: ConversationStage[] = [];
  for (const stage of stages) {
    const rounds: ConversationRound[] = [];
    for (const round of stage.rounds) {
      const items = round.items.filter(
        (item) =>
          (filter.groups.size === 0 || filter.groups.has(groupOf(item.kind))) &&
          (filter.agents.size === 0 || (item.speaker ? filter.agents.has(item.speaker) : false)),
      );
      if (items.length > 0) rounds.push({ round: round.round, items });
    }
    if (rounds.length > 0) out.push({ ...stage, rounds });
  }
  return out;
}

/** How many tool calls each agent has made, from the run's own feed. */
export function toolCallsFromFeed(events: readonly RunEvent[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const event of events) {
    if (event.type !== "tool_call_finished") continue;
    const agent = text(event.data?.agent);
    if (!agent) continue;
    counts[agent] = (counts[agent] ?? 0) + 1;
  }
  return counts;
}

/** The last thing the run said about its own status. */
export function runStatus(events: readonly RunEvent[]): string | null {
  let status: string | null = null;
  for (const event of events) {
    if (event.type === "status_change") status = text(event.data?.status) || status;
    if (event.type === "completed") status = text(event.data?.status) || "completed";
    if (event.type === "error") status = "failed";
    if (event.type === "cancelled") status = "cancelled";
  }
  return status;
}
