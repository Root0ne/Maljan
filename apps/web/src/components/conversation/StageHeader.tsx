"use client";

/* Where one part of the run begins.
 *
 * A stage is the room the next few messages were said in, so it is drawn as a
 * full-width rule with the team's own label on it rather than as another
 * card. A stage that declined says so, and says why, in the same place a
 * stage that ran says how long it took — the reader never has to look
 * somewhere else to find out why a part of the conversation is empty.
 */

import { CircleCheck, CircleDot, SkipForward } from "lucide-react";

import type { StageState } from "@/lib/conversation";
import { formatStageDuration } from "@/components/analysis/stageTimeline";

const STATE_ICON = {
  running: CircleDot,
  done: CircleCheck,
  skipped: SkipForward,
  pending: CircleDot,
};

const STATE_TEXT: Record<StageState, string> = {
  running: "text-status-blue",
  done: "text-status-green",
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
    <div className="flex items-center gap-3 pt-2">
      <span className={`flex items-center gap-1.5 ${STATE_TEXT[state]}`}>
        <Icon size={13} aria-hidden="true" />
        <span className="text-xs font-medium text-text-primary">{label}</span>
      </span>
      {kind && <span className="font-mono text-[11px] text-text-muted">{kind}</span>}
      <span className={`text-[11px] uppercase tracking-wider ${STATE_TEXT[state]}`}>{state}</span>
      {duration && <span className="font-mono text-[11px] text-text-muted">{duration}</span>}
      {state === "skipped" && reason && (
        <span className="truncate text-[11px] text-text-muted">{reason}</span>
      )}
      <span aria-hidden="true" className="h-px flex-1 bg-border" />
    </div>
  );
}
