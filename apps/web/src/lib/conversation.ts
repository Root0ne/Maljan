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

import { rosterNames } from "@/lib/rosterNames";
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
  /** Lines this participant has said. How many calls it made is counted from
   *  the feed by `toolCallsFromFeed`, which is the one place that counts. */
  messages: number;
}

export interface Conversation {
  participants: Participant[];
  stages: ConversationStage[];
  /** Characters of text the conversation holds. A streamed turn grows this
   *  without adding a line, which is how a reader following the tail knows
   *  there is more to see. */
  textLength: number;
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

/** Where an item sits, so a later event can replace it without searching. */
interface Slot {
  stage: StageDraft;
  index: number;
}

/**
 * Everything the walk carries between events.
 *
 * Kept rather than rebuilt, because a run publishes its feed in pieces: the
 * back-fill, then the socket's resume, then one frame at a time. Folding the
 * whole run again on each of those is what made a long replay freeze the tab.
 */
interface BuilderState {
  stages: Map<string, StageDraft>;
  order: string[];
  names: Map<string, string>;
  participants: Map<string, Participant>;
  streaming: Map<string, Slot>;
  pending: Map<string, Slot[]>;
  /** How many events of the array have been folded. */
  consumed: number;
  /** The last event folded, which is how a continuation is recognised. */
  last: RunEvent | null;
  /** Total characters of speech held, which is what a delta grows. */
  textLength: number;
}

/** The pipeline itself, rather than a member of the team. A watcher nobody
 *  composed — the mediator, the sycophancy detector — speaks under this key
 *  and names itself in the line, so it is drawn as a notice to the room. */
const ROOM_SPEAKER = "pipeline";

function freshState(roster: JobRoster | null): BuilderState {
  const state: BuilderState = {
    stages: new Map(),
    order: [],
    names: new Map(),
    participants: new Map(),
    streaming: new Map(),
    pending: new Map(),
    consumed: 0,
    last: null,
    textLength: 0,
  };
  /* The one reading of the roster, with this view's own fallback: a bubble
   * reads better with a key made readable than with the key. */
  const names = rosterNames(roster, prettyName);
  for (const stage of roster?.stages ?? []) {
    state.names.set(`stage:${stage.key}`, names.stage(stage.key));
  }
  for (const agent of roster?.agents ?? []) {
    const name = names.agent(agent.key);
    state.names.set(agent.key, name);
    state.participants.set(agent.key, {
      key: agent.key,
      name,
      role: agent.role,
      stages: agent.stages ?? [],
      via: agent.via ?? [],
      state: "waiting",
      messages: 0,
    });
  }
  return state;
}

function nameOf(state: BuilderState, key: string, given?: string): string {
  if (given) {
    state.names.set(key, given);
    return given;
  }
  return state.names.get(key) ?? prettyName(key);
}

function participantOf(state: BuilderState, key: string, given?: string): Participant | null {
  if (!key || key === ROOM_SPEAKER) return null;
  const existing = state.participants.get(key);
  if (existing) {
    if (given) existing.name = given;
    return existing;
  }
  const created: Participant = {
    key,
    name: nameOf(state, key, given),
    role: "",
    stages: [],
    via: [],
    state: "waiting",
    messages: 0,
  };
  state.participants.set(key, created);
  return created;
}

function draftOf(state: BuilderState, key: string): StageDraft {
  const existing = state.stages.get(key);
  if (existing) return existing;
  const created: StageDraft = {
    key,
    label: state.names.get(`stage:${key}`) ?? (key ? prettyName(key) : ""),
    kind: "",
    state: key ? "pending" : "running",
    reason: "",
    durationMs: 0,
    items: [],
    round: 0,
  };
  state.stages.set(key, created);
  state.order.push(key);
  return created;
}

function push(state: BuilderState, stage: StageDraft, item: ConversationItem): Slot {
  stage.items.push(item);
  state.textLength += item.text.length;
  return { stage, index: stage.items.length - 1 };
}

/** Swap one item for a changed copy. A new object, never a mutation: an item
 *  a reader can still see is a rendered row, and a row only redraws when the
 *  thing it draws is a different object. */
function replace(state: BuilderState, slot: Slot, next: ConversationItem): void {
  const previous = slot.stage.items[slot.index];
  state.textLength += next.text.length - (previous?.text.length ?? 0);
  slot.stage.items[slot.index] = next;
}

/** The room speaks as nobody: the line names its own watcher, and the console
 *  draws it centred rather than adding a participant the team never had. */
function speakerOf(raw: string): string {
  return raw === ROOM_SPEAKER ? "" : raw;
}

function fold(state: BuilderState, event: RunEvent): void {
  const data = event.data ?? {};
  const stageKey = text(data.stage);
  /* Keyed by the publisher's number, and by arrival order when a run has no
   * numbers — never by position in the array, which moves when an earlier
   * event arrives late and would remount every row after it. */
  const id = event.seq !== undefined ? `seq:${event.seq}` : `n:${event.order}`;

  if (
    event.type === "stage_started" ||
    event.type === "stage_skipped" ||
    event.type === "stage_finished"
  ) {
    const stage = draftOf(state, stageKey);
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
    return;
  }

  if (event.type === "agent_progress") {
    const who = participantOf(state, text(data.agent));
    const phase = text(data.phase);
    if (who) {
      if (phase === "done") who.state = "done";
      else if (phase === "analyzing") who.state = "working";
      else who.state = "waiting";
    }
    return;
  }

  if (event.type === "agent_message_delta") {
    const speaker = text(data.agent);
    if (!speaker) return;
    const stage = draftOf(state, stageKey);
    const who = participantOf(state, speaker);
    if (who) who.state = "working";
    const openKey = `${stageKey}|${speaker}`;
    const open = state.streaming.get(openKey);
    if (open) {
      const current = open.stage.items[open.index];
      replace(state, open, { ...current, text: current.text + text(data.text_delta) });
      return;
    }
    const item: ConversationItem = {
      id,
      kind: "says",
      stage: stageKey,
      round: stage.round,
      speaker,
      displayName: nameOf(state, speaker),
      text: text(data.text_delta),
      ts: event.ts,
      seq: event.seq,
      claims: [],
      dissent: [],
      streaming: true,
    };
    state.streaming.set(openKey, push(state, stage, item));
    return;
  }

  if (event.type === "agent_message") {
    const raw = text(data.speaker);
    const speaker = speakerOf(raw);
    const stage = draftOf(state, stageKey);
    const round = Number(data.round ?? 0) || 0;
    stage.round = round;
    const kind = kindOf(data.kind);
    const openKey = `${stageKey}|${speaker}`;
    const open = state.streaming.get(openKey);
    if (open) {
      /* The finished message replaces what was streamed: the publisher sends
       * the whole line once the turn closes, and keeping both would show it
       * twice. */
      state.textLength -= open.stage.items[open.index]?.text.length ?? 0;
      open.stage.items.splice(open.index, 1);
      reindexAfter(state, open);
      state.streaming.delete(openKey);
    }
    const who = participantOf(state, speaker, text(data.display_name) || undefined);
    if (who) {
      who.messages += 1;
      /* A line that closes a turn leaves its speaker done; an ask, an answer
       * or a tool line means it is still working. */
      who.state = kind === "says" || kind === "verdict" ? "done" : "working";
    }
    const addressedTo = text(data.addressed_to) || undefined;
    push(state, stage, {
      id,
      kind,
      stage: stageKey,
      round,
      speaker,
      displayName: speaker ? nameOf(state, speaker, text(data.display_name) || undefined) : "",
      addressedTo,
      addressedToName: addressedTo ? nameOf(state, addressedTo) : undefined,
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
              /* A message that reports a result is a call that answered; only
               * one that announces a call is still running. */
              ok: data.kind === "tool_result" ? data.ok !== false : null,
              durationMs: Number(data.duration_ms ?? 0) || 0,
              summary: text(data.text),
            },
          }
        : {}),
    });
    return;
  }

  if (event.type === "tool_call_started") {
    const speaker = text(data.agent);
    const stage = draftOf(state, stageKey);
    const who = participantOf(state, speaker);
    if (who) who.state = "working";
    const slot = push(state, stage, {
      id,
      kind: "tool_call",
      stage: stageKey,
      round: stage.round,
      speaker,
      displayName: nameOf(state, speaker),
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
    });
    const key = `${stageKey}|${speaker}|${text(data.tool)}`;
    const queue = state.pending.get(key) ?? [];
    queue.push(slot);
    state.pending.set(key, queue);
    return;
  }

  if (event.type === "tool_call_finished") {
    const speaker = text(data.agent);
    const stage = draftOf(state, stageKey);
    participantOf(state, speaker);
    const key = `${stageKey}|${speaker}|${text(data.tool)}`;
    const queue = state.pending.get(key) ?? [];
    const started = queue.shift();
    state.pending.set(key, queue);
    const detail: ToolDetail = {
      name: text(data.tool),
      server: text(data.server) || null,
      evidenceId: text(data.evidence_id),
      ok: data.ok !== false,
      durationMs: Number(data.duration_ms ?? 0) || 0,
      summary: text(data.summary),
    };
    if (started) {
      const current = started.stage.items[started.index];
      replace(state, started, {
        ...current,
        tool: detail,
        text: detail.summary || current.text,
      });
      return;
    }
    push(state, stage, {
      id,
      kind: "tool_call",
      stage: stageKey,
      round: stage.round,
      speaker,
      displayName: nameOf(state, speaker),
      text: detail.summary,
      ts: event.ts,
      seq: event.seq,
      claims: [],
      dissent: [],
      tool: detail,
    });
    return;
  }

  if (event.type === "validation_feedback") {
    const speaker = text(data.agent);
    const stage = draftOf(state, stageKey);
    push(state, stage, {
      id,
      kind: "validation_feedback",
      stage: stageKey,
      round: stage.round,
      speaker,
      displayName: nameOf(state, speaker),
      text: text(data.message),
      ts: event.ts,
      seq: event.seq,
      claims: [],
      dissent: [],
      code: text(data.code),
      retryIndex: Number(data.retry_index ?? 0) || 0,
    });
    return;
  }

  if (event.type === "judge_question") {
    const stage = draftOf(state, stageKey);
    const addressedTo = text(data.addressed_to) || undefined;
    push(state, stage, {
      id,
      kind: "judge_question",
      stage: stageKey,
      round: stage.round,
      speaker: "judge",
      displayName: nameOf(state, "judge"),
      addressedTo,
      addressedToName: addressedTo ? nameOf(state, addressedTo) : undefined,
      text: text(data.text),
      ts: event.ts,
      seq: event.seq,
      claims: [],
      dissent: [],
    });
    return;
  }

  if (event.type === "stage_ended_at_cap") {
    const stage = draftOf(state, stageKey);
    const agent = text(data.agent);
    push(state, stage, {
      id,
      kind: "system",
      stage: stageKey,
      round: stage.round,
      speaker: "",
      displayName: "",
      text: `${nameOf(state, agent)} stopped on its ${text(data.cap)} cap${
        text(data.detail) ? ` — ${text(data.detail)}` : ""
      }.`,
      ts: event.ts,
      seq: event.seq,
      claims: [],
      dissent: [],
    });
  }
}

/** Pull back the slots that sat after one that was removed. */
function reindexAfter(state: BuilderState, removed: Slot): void {
  for (const slot of state.streaming.values()) {
    if (slot.stage === removed.stage && slot.index > removed.index) slot.index -= 1;
  }
  for (const queue of state.pending.values()) {
    for (const slot of queue) {
      if (slot.stage === removed.stage && slot.index > removed.index) slot.index -= 1;
    }
  }
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

function snapshot(state: BuilderState): Conversation {
  return {
    participants: [...state.participants.values()].map((p) => ({ ...p })),
    textLength: state.textLength,
    stages: state.order.map((key) => {
      const stage = state.stages.get(key) as StageDraft;
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

/* One walk, continued rather than repeated.
 *
 * The store appends to its event array, so the usual call is the previous
 * array plus a few events. The cache recognises that by identity — same
 * roster, and the last event already folded still sitting where it was — and
 * folds only what is new, which keeps every item object a reader is already
 * looking at, so a memoised row does not redraw because somebody else spoke.
 * Anything else starts again from the first event. */
let cache: {
  events: readonly RunEvent[];
  roster: JobRoster | null;
  state: BuilderState;
  result: Conversation;
} | null = null;

export function buildConversation(
  events: readonly RunEvent[],
  roster: JobRoster | null,
): Conversation {
  if (cache && cache.events === events && cache.roster === roster) return cache.result;

  const continues =
    cache !== null &&
    cache.roster === roster &&
    events.length >= cache.state.consumed &&
    (cache.state.consumed === 0 || events[cache.state.consumed - 1] === cache.state.last);
  const state = continues && cache ? cache.state : freshState(roster);

  for (let i = state.consumed; i < events.length; i += 1) {
    fold(state, events[i]);
  }
  state.consumed = events.length;
  state.last = events.length > 0 ? events[events.length - 1] : null;

  const result = snapshot(state);
  cache = { events, roster, state, result };
  return result;
}

/** Forget the walk in progress. The store's own tests share a module. */
export function resetConversationCache(): void {
  cache = null;
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

/* The feed's own answer to "how much work did each agent do", held so that a
 * re-render does not re-count a run that has not changed. */
let counts: { events: readonly RunEvent[]; result: Record<string, number> } | null = null;

/** How many tool calls each agent has made, from the run's own feed. */
export function toolCallsFromFeed(events: readonly RunEvent[]): Record<string, number> {
  if (counts && counts.events === events) return counts.result;
  const result: Record<string, number> = {};
  for (const event of events) {
    if (event.type !== "tool_call_finished") continue;
    const agent = text(event.data?.agent);
    if (!agent) continue;
    result[agent] = (result[agent] ?? 0) + 1;
  }
  counts = { events, result };
  return result;
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
