"use client";

/* The team, as a strip of stages.
 *
 * It lives on the analysis header and only there: the shape of a run is a
 * property of the run, not of the tab being read, so every tab shows the same
 * strip in the same place rather than each drawing its own. Live stage events
 * are laid over the stored rollup by `stageTimeline`, which is what lets a
 * stage that has not happened yet appear beside one that just finished.
 */

import { formatStageDuration, type StageTimelineRow } from "./stageTimeline";

const STATUS_STYLE: Record<string, string> = {
  running: "border-status-blue/30 bg-status-blue/10 text-status-blue",
  done: "border-status-green/30 bg-status-green/10 text-status-green",
  skipped: "border-border bg-bg-surface text-text-muted",
  pending: "border-border bg-bg-surface text-text-disabled",
};

export default function PipelineStrip({ stages }: { stages: StageTimelineRow[] }) {
  if (stages.length === 0) return null;
  return (
    <div className="mt-3 flex flex-wrap gap-2" data-testid="pipeline-strip">
      {stages.map((stage) => (
        <span
          key={stage.key}
          className={`flex items-baseline gap-2 rounded border px-2 py-1 text-[11px] ${
            STATUS_STYLE[stage.status] ?? STATUS_STYLE.pending
          }`}
          title={stage.reason || `${stage.kind} stage`}
        >
          <span className="font-mono">{stage.key}</span>
          <span className="uppercase tracking-wider">{stage.status}</span>
          {formatStageDuration(stage.duration_ms) && (
            <span className="font-mono">{formatStageDuration(stage.duration_ms)}</span>
          )}
        </span>
      ))}
    </div>
  );
}
