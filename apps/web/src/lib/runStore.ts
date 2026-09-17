/* One run, one store, one socket.
 *
 * Everything the console knows about a live analysis lives here, keyed by job
 * id, in a module-level map that outlives every component that reads it. A
 * route change costs nothing: the layout unsubscribes, the socket stays open
 * for a grace period, and the next subscriber gets the events that were
 * already held rather than a fresh dial and a fresh back-fill.
 *
 * The publisher numbers every event with a job-wide `seq`, and that number is
 * three things at once here: the ordering key, the dedupe identity and the
 * cursor a reconnect resumes from. A run recorded before the numbering
 * existed carries none, so those events keep the order they arrived in and
 * are deduped on what they do carry. Neither path throws on a missing number.
 *
 * The transport is replaceable, which is what makes the socket schedule
 * testable without a browser: `configureRunTransport` swaps the pair of calls
 * that reach the network, and nothing else in this module knows what a
 * WebSocket is.
 */

import { stageTimeline } from "@/components/analysis/stageTimeline";
import type { StageEvent, StageTimelineRow } from "@/components/analysis/stageTimeline";
import type { StageRow } from "@/components/analysis/pipelineSteps";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { TranscriptRow } from "@/lib/conversation";
import type { JobRoster } from "@/types";

/* ── Shape ─────────────────────────────────────────────── */

/** Where the socket stands. `unauthorized` is terminal: the credential has to
 *  be replaced before another dial can succeed, so nothing retries. */
export type RunConnection =
  | "idle"
  | "connecting"
  | "open"
  | "reconnecting"
  | "closed"
  | "unauthorized";

/** One event as it arrives, from either reader. Deliberately looser than the
 *  published union: an event type this console has never heard of is held and
 *  ignored, never a reason to drop the feed. */
export interface IncomingEvent {
  type: string;
  data?: Record<string, unknown> | null;
  ts?: string | null;
  stream_id?: string;
}

/** One event, as the store holds it. */
export interface RunEvent {
  type: string;
  data: Record<string, unknown>;
  ts: string;
  /** Present only on an event the Redis stream answered. */
  stream_id?: string;
  /** The publisher's number. Absent on a run recorded before there were any. */
  seq?: number;
  /** Arrival order, which is what orders a run that has no numbers. */
  order: number;
  /** What the store sorts on: the publisher's number when there is one, and
   *  otherwise a position just past the last number held when this arrived —
   *  so an unnumbered line stays where it turned up rather than being swept
   *  to the end of a run that has numbers elsewhere. */
  sortKey: number;
}

export interface RunState {
  jobId: string;
  /** Every event this run has published, in `seq` order. */
  events: RunEvent[];
  /** The highest `seq` held, which is the cursor a resume asks from. */
  lastSeq: number;
  roster: JobRoster | null;
  /** The team as a list of stages, live events over the stored rollup. */
  stages: StageTimelineRow[];
  connection: RunConnection;
  /** What went wrong reading the recorded feed, when something did. */
  feedError: string | null;
}

/* ── Transport ─────────────────────────────────────────── */

export interface RunSocket {
  close(): void;
}

export interface RunSocketHandlers {
  onOpen(): void;
  onEvent(event: IncomingEvent): void;
  onClose(code: number): void;
}

export interface RunTransport {
  /** The recorded feed from `seq` onwards; omit the cursor for the whole run. */
  readEvents(jobId: string, since?: number): Promise<IncomingEvent[]>;
  /** A live subscription resuming after `since`. */
  connect(jobId: string, since: number, handlers: RunSocketHandlers): RunSocket;
}

function defaultWsBase(): string {
  const base = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
  return (process.env.NEXT_PUBLIC_WS_URL || base).replace(/^http/, "ws");
}

/* Reconnect schedule: exponential backoff with full jitter, so a backend
 * restart does not turn every open tab into a retry storm. Reset on open. */
const BASE_DELAY_MS = 1_000;
const MAX_DELAY_MS = 30_000;

/** Close codes that mean the credential was rejected rather than the
 *  connection dropped. Redialling would resend the same bad token. */
const NO_RETRY_CLOSE_CODES = new Set([1008, 4401]);

/** How long a socket outlives its last reader, so a route change costs
 *  nothing and a tab left on another page does not hold one open forever. */
const GRACE_MS = 30_000;

/** How much of the recorded feed one back-fill asks for. What it does not
 *  reach, the socket's own resume carries. */
const BACKFILL_LIMIT = 1000;

function backoffDelay(attempt: number): number {
  const ceiling = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** attempt);
  return Math.floor(Math.random() * ceiling);
}

const browserTransport: RunTransport = {
  async readEvents(jobId, since) {
    const response = await api.getJobEvents(jobId, BACKFILL_LIMIT, since);
    return (response.events ?? []).map((event) => ({
      type: event.type,
      data: event.data ?? {},
      ts: event.ts ?? "",
      stream_id: event.stream_id,
    }));
  },
  connect(jobId, since, handlers) {
    /* The token travels as a subprotocol, never in the URL: a query string
     * ends up in proxy logs and in the Referer header. `since` is the only
     * thing on the URL, and it is a sequence number. */
    const token =
      typeof window !== "undefined" ? localStorage.getItem("access_token") : null;
    const url = `${defaultWsBase()}/ws/analysis/${jobId}?since=${since}`;
    const protocols = token ? ["maljan.v1", `maljan.v1.${token}`] : ["maljan.v1"];
    const ws = new WebSocket(url, protocols);

    ws.onopen = () => handlers.onOpen();
    ws.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data) as IncomingEvent;
        if (event.type === "heartbeat" || event.type === "pong") return;
        handlers.onEvent(event);
      } catch {
        /* A malformed frame is dropped rather than allowed to break the feed. */
      }
    };
    ws.onclose = (event) => handlers.onClose(event.code);
    ws.onerror = () => ws.close();

    return { close: () => ws.close() };
  },
};

let transport: RunTransport = browserTransport;

/** Replace the two calls that reach the network. Tests use this to drive the
 *  back-fill and the socket schedule without a browser. */
export function configureRunTransport(next: RunTransport | null): void {
  transport = next ?? browserTransport;
}

/* ── The map ───────────────────────────────────────────── */

interface RunEntry {
  state: RunState;
  listeners: Set<() => void>;
  /** Identity of every event held, so a replay cannot draw one twice. */
  seen: Set<string>;
  stageEvents: StageEvent[];
  storedStages: StageRow[] | null;
  socket: RunSocket | null;
  readers: number;
  attempt: number;
  /** Whether the recorded feed has been asked for. */
  asked: boolean;
  retryTimer: ReturnType<typeof setTimeout> | null;
  closeTimer: ReturnType<typeof setTimeout> | null;
  arrivals: number;
  /** The recorded conversation, held until the feed has had its say. */
  transcript: TranscriptRow[] | null;
  /** Whether the recorded feed has answered, however it answered. */
  backfilled: boolean;
  /** Frames that have arrived but are not folded in yet. */
  pending: IncomingEvent[];
  /** Whether a commit is already scheduled for those frames. */
  flushing: boolean;
  /** When this run was last subscribed to, for eviction order. */
  touched: number;
}

const runs = new Map<string, RunEntry>();

/** How many runs a session keeps in memory. A reader moves between a handful
 *  of runs and expects each to be there when they come back; beyond that the
 *  oldest run nobody is reading is dropped rather than held for the life of
 *  the tab. */
const MAX_RUNS = 5;

let clock = 0;

function evictIdleRuns(): void {
  if (runs.size <= MAX_RUNS) return;
  const idle = [...runs.values()]
    .filter((entry) => entry.readers === 0 && entry.listeners.size === 0)
    .sort((a, b) => a.touched - b.touched);
  for (const entry of idle) {
    if (runs.size <= MAX_RUNS) break;
    resetRun(entry.state.jobId);
  }
}

const STAGE_EVENTS = new Set(["stage_started", "stage_skipped", "stage_finished"]);

function emptyState(jobId: string): RunState {
  return {
    jobId,
    events: [],
    lastSeq: 0,
    roster: null,
    stages: [],
    connection: "idle",
    feedError: null,
  };
}

/** The state a component reading no job sees. One frozen object, because
 *  `useSyncExternalStore` compares snapshots by identity. */
const NO_RUN: RunState = Object.freeze(emptyState(""));

function entryFor(jobId: string): RunEntry {
  const existing = runs.get(jobId);
  if (existing) return existing;
  const created: RunEntry = {
    state: emptyState(jobId),
    listeners: new Set(),
    seen: new Set(),
    stageEvents: [],
    storedStages: null,
    socket: null,
    readers: 0,
    attempt: 0,
    asked: false,
    backfilled: false,
    retryTimer: null,
    closeTimer: null,
    arrivals: 0,
    transcript: null,
    pending: [],
    flushing: false,
    touched: clock,
  };
  runs.set(jobId, created);
  return created;
}

function publish(entry: RunEntry): void {
  for (const listener of [...entry.listeners]) listener();
}

function patch(entry: RunEntry, next: Partial<RunState>): void {
  entry.state = { ...entry.state, ...next };
  publish(entry);
}

function asSeq(value: unknown): number | undefined {
  const seq = Number(value);
  return Number.isFinite(seq) && seq > 0 ? seq : undefined;
}

/** What makes two copies of one event the same event. The publisher's number
 *  when there is one, the stream id when the stream answered, and otherwise
 *  the content — which is all a run from before the numbering carries. */
function identity(event: RunEvent): string {
  if (event.seq !== undefined) return `s${event.seq}`;
  if (event.stream_id) return `x${event.stream_id}`;
  return `k${event.type}|${event.ts}|${JSON.stringify(event.data)}`;
}

/* ── Writing ───────────────────────────────────────────── */

/**
 * When a batch of frames becomes one commit.
 *
 * A resume arrives as a burst — the server replays a long run one frame at a
 * time — and folding, copying and re-rendering once per frame is what made a
 * three-thousand-event run freeze the tab it opened in. Frames are collected
 * and committed together: once per animation frame in a browser, and once per
 * microtask anywhere else, so a test sees the same batching without a clock.
 */
function scheduleFlush(run: () => void): void {
  if (typeof requestAnimationFrame === "function") requestAnimationFrame(() => run());
  else queueMicrotask(run);
}

/**
 * Hold one event for the next commit.
 *
 * Used by the socket, which is the only reader that arrives one frame at a
 * time. The back-fill already has its whole answer and folds it in one call.
 */
function queueRunEvent(jobId: string, event: IncomingEvent): void {
  const entry = entryFor(jobId);
  entry.pending.push(event);
  if (entry.flushing) return;
  entry.flushing = true;
  scheduleFlush(() => {
    const current = runs.get(jobId);
    if (!current) return;
    current.flushing = false;
    const batch = current.pending;
    current.pending = [];
    if (batch.length > 0) applyRunEvents(jobId, batch);
  });
}

/**
 * Fold a batch of events into a run.
 *
 * Idempotent: the back-fill, the socket's own resume and the live feed overlap
 * by design, and an event already held is dropped rather than drawn twice.
 */
export function applyRunEvents(jobId: string, incoming: IncomingEvent[]): void {
  const entry = entryFor(jobId);
  const added: RunEvent[] = [];

  let anchor = entry.state.lastSeq;
  for (const raw of incoming) {
    if (!raw || typeof raw.type !== "string") continue;
    if (raw.type === "heartbeat" || raw.type === "pong") continue;
    const data = (raw.data ?? {}) as Record<string, unknown>;
    const seq = asSeq(data.seq);
    const event: RunEvent = {
      type: raw.type,
      data,
      ts: typeof raw.ts === "string" ? raw.ts : "",
      stream_id: raw.stream_id,
      seq,
      order: entry.arrivals,
      sortKey: seq ?? anchor + (entry.arrivals + 1) / 1e9,
    };
    const key = identity(event);
    if (entry.seen.has(key)) continue;
    entry.seen.add(key);
    entry.arrivals += 1;
    if (seq !== undefined && seq > anchor) anchor = seq;
    added.push(event);
  }

  if (added.length === 0) return;

  /* The common case is a batch that belongs at the end, so only the batch and
   * the seam it lands on are checked. Scanning the whole run for order on
   * every commit was O(n) per frame on a feed that is already sorted. */
  const held = entry.state.events;
  let ordered = held.length === 0 || added[0].sortKey >= held[held.length - 1].sortKey;
  for (let i = 1; ordered && i < added.length; i += 1) {
    if (added[i].sortKey < added[i - 1].sortKey) ordered = false;
  }
  const events = [...held, ...added];
  if (!ordered) {
    events.sort((a, b) => a.sortKey - b.sortKey || a.order - b.order);
  }

  let lastSeq = entry.state.lastSeq;
  let roster = entry.state.roster;
  for (const event of added) {
    if (event.seq !== undefined && event.seq > lastSeq) lastSeq = event.seq;
    if (STAGE_EVENTS.has(event.type)) entry.stageEvents.push({ type: event.type, data: event.data });
    /* The run names its own cast before anybody speaks. A reader who opened
     * the job already has the same roster from the job endpoint; whichever
     * arrives first is the one kept, because they say the same thing. */
    if (event.type === "roster" && !roster && Array.isArray(event.data.agents)) {
      roster = {
        agents: event.data.agents as JobRoster["agents"],
        stages: (Array.isArray(event.data.stages) ? event.data.stages : []) as JobRoster["stages"],
      };
    }
  }

  const stages = added.some((event) => STAGE_EVENTS.has(event.type))
    ? stageTimeline(entry.stageEvents, entry.storedStages)
    : entry.state.stages;

  patch(entry, { events, lastSeq, stages, roster });
}

/**
 * Name the participants.
 *
 * The roster arrives twice by design — on `GET /jobs/{id}` and as the run's
 * first event — because a reader who opens a finished run needs names as much
 * as a reader watching a live one. Whichever arrives first wins; both say the
 * same thing.
 */
export function setRunRoster(jobId: string, roster: JobRoster | null): void {
  if (!roster) return;
  const entry = entryFor(jobId);
  if (entry.state.roster) return;
  patch(entry, { roster });
}

/** The stage rollup a finished report carries, which is the only source that
 *  knows about the stages a run has not reached yet. */
export function setRunStoredStages(jobId: string, stored: StageRow[] | null): void {
  const entry = entryFor(jobId);
  const same =
    (entry.storedStages?.length ?? 0) === (stored?.length ?? 0) &&
    (entry.storedStages ?? []).every((row, i) => row.key === stored?.[i]?.key && row.ran === stored?.[i]?.ran);
  if (same) return;
  entry.storedStages = stored;
  patch(entry, { stages: stageTimeline(entry.stageEvents, stored) });
}

/**
 * Offer the recorded conversation.
 *
 * A run whose feed predates the event recording has no events to replay at
 * all, and its `agent_messages` rows are the only copy of what was said. They
 * are held rather than folded in: whether they are needed is a question only
 * the feed can answer, and it answers when the back-fill returns.
 */
export function hydrateRunTranscript(jobId: string, rows: TranscriptRow[] | null | undefined): void {
  if (!rows?.length) return;
  const entry = entryFor(jobId);
  if (entry.transcript) return;
  entry.transcript = rows;
  hydrate(entry);
}

/** Forget a run entirely, socket included. */
export function resetRun(jobId: string): void {
  const entry = runs.get(jobId);
  if (!entry) return;
  if (entry.retryTimer) clearTimeout(entry.retryTimer);
  if (entry.closeTimer) clearTimeout(entry.closeTimer);
  entry.pending = [];
  entry.readers = 0;
  entry.socket?.close();
  entry.socket = null;
  runs.delete(jobId);
}

/* ── The socket ────────────────────────────────────────── */

function dial(entry: RunEntry): void {
  if (entry.socket || entry.readers === 0) return;
  const jobId = entry.state.jobId;
  patch(entry, { connection: entry.attempt === 0 ? "connecting" : "reconnecting" });

  entry.socket = transport.connect(jobId, entry.state.lastSeq, {
    onOpen() {
      entry.attempt = 0;
      patch(entry, { connection: "open" });
    },
    onEvent(event) {
      queueRunEvent(jobId, event);
    },
    onClose(code) {
      entry.socket = null;
      if (NO_RETRY_CLOSE_CODES.has(code)) {
        patch(entry, { connection: "unauthorized" });
        return;
      }
      if (entry.readers === 0) {
        patch(entry, { connection: "closed" });
        return;
      }
      const delay = backoffDelay(entry.attempt);
      entry.attempt += 1;
      patch(entry, { connection: "reconnecting" });
      entry.retryTimer = setTimeout(() => {
        entry.retryTimer = null;
        dial(entry);
      }, delay);
    },
  });
}

async function backfill(entry: RunEntry): Promise<void> {
  if (entry.asked) return;
  entry.asked = true;
  const jobId = entry.state.jobId;
  try {
    /* No cursor on the first read: the whole run, from its first event, which
     * the events table answers once the stream has been trimmed. */
    const events = await transport.readEvents(jobId);
    applyRunEvents(jobId, events);
    if (entry.state.feedError) patch(entry, { feedError: null });
  } catch (error) {
    patch(entry, {
      feedError: `Earlier events could not be replayed (${getErrorMessage(error)}). The conversation starts from here.`,
    });
  } finally {
    entry.backfilled = true;
    hydrate(entry);
  }
}

/**
 * Fall back to the recorded conversation, once it is clear there is no feed.
 *
 * Only then: a run that still has its events replays from them, and stored
 * rows laid over a feed would be the same conversation twice — a row numbered
 * by an older scheme can even carry a number a live event is already using,
 * which would shadow the real thing rather than merely repeat it.
 */
/** The speaker a watcher of the run publishes under; see `nodes.ROOM_SPEAKER`. */
const ROOM_SPEAKER = "pipeline";

/**
 * The kind a stored row would have gone out under.
 *
 * Stored rows carry no `kind` — the column postdates them — so it is derived
 * the way the publisher derives it. The judge closes the run; the room's own
 * watchers, the mediator and the sycophancy detector, are notices whatever
 * role they were filed under, and drawing one as a participant would add a
 * speaker to a team nobody composed.
 */
function kindOfStoredRow(row: TranscriptRow): string {
  if (row.speaker === ROOM_SPEAKER) return "system";
  if (row.role === "judge") return "verdict";
  if (row.role === "system" || row.role === "negotiator") return "system";
  return "says";
}

function hydrate(entry: RunEntry): void {
  const rows = entry.transcript;
  if (!rows?.length || !entry.backfilled) return;
  /* What the stored rows stand in for is the conversation, not the feed. A
   * back-fill that answered with a roster, some stage markers and the tool
   * calls but no line anybody said is a run whose speech was never recorded as
   * events, and the recorded conversation is still the only copy of it. */
  if (entry.state.events.some((e) => e.type === "agent_message")) return;
  entry.transcript = null;
  applyRunEvents(
    entry.state.jobId,
    rows.map((row) => ({
      type: "agent_message",
      ts: row.ts ?? "",
      data: {
        speaker: row.speaker,
        role: row.role,
        round: row.round,
        status: row.status,
        text: row.text,
        kind: kindOfStoredRow(row),
        stage: row.stage ?? undefined,
        addressed_to: row.addressed_to ?? undefined,
        confidence: row.confidence ?? undefined,
        claims: row.claims,
        dissent: row.dissent,
        report: row.report ?? undefined,
        report_truncated: row.report_truncated,
      },
    })),
  );
}

/**
 * Read a run, and keep it alive while anybody is reading.
 *
 * The first subscriber opens the feed: the recorded events first, then the
 * socket resuming from the last number held, so nothing published between the
 * two reads is lost. The last unsubscribe starts a grace timer rather than
 * closing, so leaving the page and coming back does not re-dial.
 */
export function subscribeRun(jobId: string, listener: () => void): () => void {
  const entry = entryFor(jobId);
  clock += 1;
  entry.touched = clock;
  entry.listeners.add(listener);
  entry.readers += 1;
  evictIdleRuns();
  if (entry.closeTimer) {
    clearTimeout(entry.closeTimer);
    entry.closeTimer = null;
  }
  /* A credential the server rejected is not retried by coming back to the
   * page: the token has to be replaced first, and redialling would resend the
   * same one. */
  if (!entry.socket && !entry.retryTimer && entry.state.connection !== "unauthorized") {
    void backfill(entry).then(() => {
      // The run may have been reset or evicted while the back-fill was in
      // flight; the socket belongs to the entry that asked for it.
      if (runs.get(jobId) === entry) dial(entry);
    });
  }

  return () => {
    entry.listeners.delete(listener);
    entry.readers = Math.max(0, entry.readers - 1);
    if (entry.readers > 0) return;
    entry.closeTimer = setTimeout(() => {
      entry.closeTimer = null;
      if (entry.readers > 0) return;
      if (entry.retryTimer) {
        clearTimeout(entry.retryTimer);
        entry.retryTimer = null;
      }
      entry.socket?.close();
      entry.socket = null;
      patch(entry, { connection: "closed" });
    }, GRACE_MS);
  };
}

/**
 * The current snapshot for a run.
 *
 * A read never creates anything: this is also the server snapshot, and a
 * module-level map in a rendering process that only ever grows is a leak with
 * no reader. A run the store has not been told about reads as the empty one
 * until something subscribes to it.
 */
export function getRun(jobId: string | null): RunState {
  if (!jobId) return NO_RUN;
  return runs.get(jobId)?.state ?? NO_RUN;
}
