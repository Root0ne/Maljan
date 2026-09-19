"use client";

/* The team, as a strip of stages.
 *
 * It lives on the analysis header and only there: the shape of a run is a
 * property of the run, not of the tab being read, so every tab shows the same
 * strip in the same place rather than each drawing its own. Live stage events
 * are laid over the stored rollup by `stageTimeline`, which is what lets a
 * stage that has not happened yet appear beside one that just finished.
 *
 * A stage and its members are named the way an operator named them. The run's
 * roster carries a label for every key it publishes, so a team of ahmet,
 * mehmet and cemal reads as such here and in the conversation rather than as
 * `ahmet_1` in one place and "ahmet" in the other.
 */

import { rosterNames } from "@/lib/rosterNames";
import type { JobRoster } from "@/types/events";
import { formatStageDuration, type StageTimelineRow } from "./stageTimeline";

const STATUS_STYLE: Record<string, string> = {
  running: "border-status-blue/30 bg-status-blue/10 text-status-blue",
  done: "border-status-green/30 bg-status-green/10 text-status-green",
  skipped: "border-border bg-bg-surface text-text-muted",
  pending: "border-border bg-bg-surface text-text-disabled",
};

export default function PipelineStrip({
  stages,
  roster = null,
}: {
  stages: StageTimelineRow[];
  roster?: JobRoster | null;
}) {
  if (stages.length === 0) return null;
  const names = rosterNames(roster);

  return (
    <div className="mt-3 flex flex-wrap gap-2" data-testid="pipeline-strip">
      {stages.map((stage) => {
        const members = stage.agents.map(names.agent);
        return (
          <span
            key={stage.key}
            className={`flex items-baseline gap-2 rounded border px-2 py-1 text-[11px] ${
              STATUS_STYLE[stage.status] ?? STATUS_STYLE.pending
            }`}
            title={stage.reason || undefined}
          >
            {/* A name rather than a key, so not monospaced: the roster's
                label where the run published one, the key where it did not. */}
            <span className="font-medium">{names.stage(stage.key)}</span>
            {/* What kind of stage this is used to live in a `title` on a
                `<span>` nothing can focus, so it reached a pointer and nobody
                else. A reason keeps its tooltip, because a reason is a
                sentence rather than a word. */}
            <span className="sr-only">{stage.kind} stage</span>
            <span className="uppercase tracking-wider">{stage.status}</span>
            {members.length > 0 && (
              <span className="text-text-muted">{members.join(", ")}</span>
            )}
            {formatStageDuration(stage.duration_ms) && (
              <span className="font-mono">{formatStageDuration(stage.duration_ms)}</span>
            )}
          </span>
        );
      })}
    </div>
  );
}
