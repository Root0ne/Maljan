"use client";

/* Where one part of the run begins.
 *
 * A stage is the room the next few messages were said in, so it is drawn the
 * way a group thread draws a date: a small chip centred in the stream, with
 * the team's own label on it, rather than another card. A stage that
 * declined says so, and says why, in the same chip a stage that ran uses to
 * say how long it took — the reader never has to look somewhere else to find
 * out why a part of the conversation is empty. The label is a heading, so a
 * screen reader can walk the run stage by stage.
 */

import { CircleCheck, CircleDot, SkipForward } from "lucide-react";

import type { StageState } from "@/lib/conversation";
import { formatStageDuration } from "@/components/analysis/stageTimeline";
import { progressTone } from "@/lib/status";

const STATE_ICON = {
  running: CircleDot,
  done: CircleCheck,
  skipped: SkipForward,
  pending: CircleDot,
};

/* Running and done are the run's own colours (`lib/status.ts`); a stage that
 * declined or has not started is muted. */
const STATE_TEXT: Record<StageState, string> = {
  running: progressTone("running").text,
  done: progressTone("done").text,
  skipped: "text-text-muted",
  pending: "text-text-muted",
};

export default function StageHeader({
  label,
  kind,
  state,
  reason,
  durationMs,
}: {
  label: string;
  kind: string;
  state: StageState;
  reason: string;
  durationMs: number;
}) {
  const Icon = STATE_ICON[state];
  const duration = formatStageDuration(durationMs);
  return (
    <div className="flex justify-center pt-3">
      <div className="flex max-w-full flex-wrap items-center justify-center gap-x-2 gap-y-0.5 rounded-full border border-border-light bg-bg-elevated px-3 py-1 text-[11px]">
        <Icon size={12} aria-hidden="true" className={STATE_TEXT[state]} />
        <h3 className="text-xs font-medium text-text-primary">{label}</h3>
        {/* The kind, where the team's label does not already say it. */}
        {kind && kind !== label.toLowerCase() && <span className="text-text-secondary">{kind}</span>}
        {/* On the elevated chip muted text falls under 4.5:1, so a muted
            state is written in the secondary colour there. */}
        <span className={STATE_TEXT[state] === "text-text-muted" ? "text-text-secondary" : STATE_TEXT[state]}>
          {state}
        </span>
        {duration && <span className="tabular-nums text-text-secondary">{duration}</span>}
        {state === "skipped" && reason && <span className="text-text-secondary">{reason}</span>}
      </div>
    </div>
  );
}
