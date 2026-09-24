/**
 * How a run's status is coloured, in one place.
 *
 * The dashboard, the analyses list, the search palette and the analysis
 * header each kept a map of their own, and they had drifted: the palette drew
 * a running job orange where every other surface drew it blue. The status
 * word is always printed beside the colour; this only keeps the colour the
 * same word everywhere.
 *
 * A stage and a participant have states of their own vocabulary — a stage is
 * `running` or `done`, a participant `working` or `done` — and they are the
 * same two facts about a part of the run, so they take the same two colours.
 */

export type RunStatus = "completed" | "running" | "pending" | "failed" | "cancelled";

export interface StatusTone {
  /** The text colour class. */
  text: string;
  /** The wash a badge is filled with. */
  bg: string;
  /** The border class a chip is outlined with. */
  border: string;
  /** A solid mark, for the dot beside a status word. */
  dot: string;
}

const TONES: Record<RunStatus, StatusTone> = {
  completed: {
    text: "text-status-green",
    bg: "bg-status-green/10",
    border: "border-status-green/30",
    dot: "bg-status-green",
  },
  running: {
    text: "text-status-blue",
    bg: "bg-status-blue/10",
    border: "border-status-blue/30",
    dot: "bg-status-blue",
  },
  pending: {
    text: "text-text-muted",
    bg: "bg-bg-active",
    border: "border-border",
    dot: "bg-text-muted",
  },
  failed: {
    text: "text-status-red",
    bg: "bg-status-red/10",
    border: "border-status-red/30",
    dot: "bg-status-red",
  },
  cancelled: {
    text: "text-text-muted",
    bg: "bg-bg-active",
    border: "border-border",
    dot: "bg-text-muted",
  },
};

/** The tone of a job status; a status this console does not know reads as
 *  pending, a muted grey that claims nothing. */
export function statusTone(status: string | null | undefined): StatusTone {
  const key = String(status ?? "").trim().toLowerCase() as RunStatus;
  return TONES[key] ?? TONES.pending;
}

/** A stage's or a participant's state, on the run's colours: in progress is
 *  `running`, finished is `completed`, and anything else is pending. */
export function progressTone(state: string | null | undefined): StatusTone {
  const key = String(state ?? "").trim().toLowerCase();
  if (key === "running" || key === "working") return TONES.running;
  if (key === "done") return TONES.completed;
  return TONES.pending;
}
