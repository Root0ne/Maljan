/**
 * The team, as a timeline of stages, from whichever record the page has.
 *
 * A run tells its own story twice. While it runs, each stage announces itself
 * on the WebSocket: `stage_started` from its first node, `stage_skipped`
 * instead when its condition is false, and `stage_finished` from the one node
 * that runs after everything in it is done. Once it has finished,
 * `run_summary.stages` is the same story written down — every stage of the
 * profile in declaration order, including the ones that declined and the
 * reason each gave.
 *
 * Both are read here, and the stored rollup is the base rather than the
 * fallback: it is the only source that knows about the stages that have not
 * happened yet. Live events are laid over it, because a stage that has just
 * started is a fact the rollup of a finished run cannot contain and the
 * rollup of an unfinished run does not exist.
 *
 * A run stored before stages existed produces no rows at all, and the panel
 * draws the flat chain it always drew.
 */

import type { StageRow } from "./pipelineSteps";

export type StageStatus = "pending" | "running" | "done" | "skipped";

export interface StageTimelineRow {
  key: string;
  kind: string;
  status: StageStatus;
  /** Why the stage declined. Empty unless it was skipped. */
  reason: string;
  agents: string[];
  duration_ms: number;
}

/** A pipeline event as the analysis layout hands it over. */
export interface StageEvent {
  type: string;
  data: Record<string, unknown>;
}

const STAGE_EVENTS = new Set(["stage_started", "stage_skipped", "stage_finished"]);

/** Whether this run has said anything about stages at all. */
export function hasStageRecord(
  events: StageEvent[] | null | undefined,
  stored: StageRow[] | null | undefined
): boolean {
  return (stored?.length ?? 0) > 0 || (events ?? []).some((e) => STAGE_EVENTS.has(e.type));
}

function asStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.map(String) : [];
}

/** Every stage of this run, in the order it happens. */
export function stageTimeline(
  events: StageEvent[] | null | undefined,
  stored: StageRow[] | null | undefined
): StageTimelineRow[] {
  const rows = new Map<string, StageTimelineRow>();

  for (const row of stored ?? []) {
    rows.set(row.key, {
      key: row.key,
      kind: row.kind,
      status: row.ran ? "done" : "skipped",
      reason: row.ran ? "" : row.reason || "did not run",
      agents: row.agents ?? [],
      duration_ms: row.duration_ms ?? 0,
    });
  }

  for (const event of events ?? []) {
    if (!STAGE_EVENTS.has(event.type)) continue;
    const key = String(event.data.stage ?? "");
    if (!key) continue;
    const current = rows.get(key) ?? {
      key,
      kind: String(event.data.kind ?? ""),
      status: "pending" as StageStatus,
      reason: "",
      agents: [],
      duration_ms: 0,
    };
    const kind = String(event.data.kind ?? "") || current.kind;
    const agents = asStrings(event.data.agents);
    if (event.type === "stage_started") {
      rows.set(key, {
        ...current,
        kind,
        status: "running",
        reason: "",
        agents: agents.length > 0 ? agents : current.agents,
      });
    } else if (event.type === "stage_skipped") {
      rows.set(key, {
        ...current,
        kind,
        status: "skipped",
        reason: String(event.data.reason ?? "") || "did not run",
        duration_ms: 0,
      });
    } else {
      rows.set(key, {
        ...current,
        kind,
        status: "done",
        reason: "",
        agents: agents.length > 0 ? agents : current.agents,
        duration_ms: Number(event.data.duration_ms ?? current.duration_ms) || 0,
      });
    }
  }

  return [...rows.values()];
}

/** A stage's duration, in the units a reader of a 30-minute run thinks in. */
export function formatStageDuration(ms: number): string {
  const value = Number(ms) || 0;
  if (value <= 0) return "";
  if (value < 1000) return `${value} ms`;
  if (value < 60_000) return `${(value / 1000).toFixed(1)} s`;
  const minutes = Math.floor(value / 60_000);
  const seconds = Math.round((value % 60_000) / 1000);
  return `${minutes}m ${seconds}s`;
}

export interface StageTiming {
  key: string;
  duration_ms: number;
  /** The stage's duration as the header strip prints it. */
  label: string;
  /** Its bar's length, as a share of the run's elapsed time in percent. */
  share: number;
}

/**
 * The stages that took time, from the rows the header strip draws.
 *
 * The same rows and the same formatter as the strip, so a stage's duration on
 * the Summary and on the strip cannot disagree. A stage that declined, or has
 * not finished, has no duration and no row. Each bar is a share of the run's
 * elapsed time when the job carries one — the gap between the bars and the
 * whole is queueing, ingestion and the writing of the report — and of the
 * stages' own sum when it does not.
 */
export function stageTiming(
  rows: StageTimelineRow[],
  elapsedSeconds: number | null | undefined,
): { stages: StageTiming[]; stagesMs: number } {
  const timed = rows.filter((row) => (Number(row.duration_ms) || 0) > 0);
  const stagesMs = timed.reduce((sum, row) => sum + row.duration_ms, 0);
  const elapsedMs = (Number(elapsedSeconds) || 0) * 1000;
  const whole = Math.max(elapsedMs, stagesMs);
  return {
    stagesMs,
    stages: timed.map((row) => ({
      key: row.key,
      duration_ms: row.duration_ms,
      label: formatStageDuration(row.duration_ms),
      share: whole > 0 ? Math.max(1, Math.round((row.duration_ms / whole) * 100)) : 0,
    })),
  };
}

/**
 * How many ledger calls each agent made, from one page of the evidence ledger.
 *
 * A count, not a list: the agents view answers "who did the work" and the
 * evidence tab answers "what work". Entries the page did not reach are not
 * counted, so the caller asks for a page large enough to mean something and
 * says what it asked for.
 */
export function toolCallsByAgent(
  entries: Array<{ agent: string }> | null | undefined
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const entry of entries ?? []) {
    const agent = String(entry.agent ?? "");
    if (!agent) continue;
    counts[agent] = (counts[agent] ?? 0) + 1;
  }
  return counts;
}
