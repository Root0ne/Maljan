"use client";

import { useState } from "react";

import AgentsPanel from "../agents/page";
import PipelinePanel from "../pipeline/page";
import TimelinePanel from "../timeline/page";

/**
 * Unified "Process" tab (2026-07 round 2).
 *
 * AGENTS, PIPELINE and TIMELINE all describe the same thing — how the
 * multi-agent run produced the verdict — and read the same post-analysis data
 * (agent_findings, negotiation_log). They are merged here under one tab with
 * three switchable sub-views so the advanced tab bar isn't crowded.
 */
type SubView = "agents" | "pipeline" | "timeline";

const SUBVIEWS: { key: SubView; label: string; hint: string }[] = [
  { key: "agents", label: "Agents", hint: "Per-agent findings summary" },
  { key: "pipeline", label: "Pipeline", hint: "Execution flow & negotiation" },
  { key: "timeline", label: "Timeline", hint: "Confidence convergence & debate" },
];

export default function ProcessTab() {
  const [view, setView] = useState<SubView>("agents");

  return (
    <div className="space-y-4">
      <div className="flex gap-1 flex-wrap">
        {SUBVIEWS.map((s) => (
          <button
            key={s.key}
            onClick={() => setView(s.key)}
            title={s.hint}
            className={`text-[11px] uppercase tracking-wider px-3 py-1 rounded border transition-colors ${
              view === s.key
                ? "border-accent text-accent"
                : "border-border text-text-secondary hover:text-text-primary"
            }`}
          >
            {s.label}
          </button>
        ))}
      </div>

      {view === "agents" && <AgentsPanel />}
      {view === "pipeline" && <PipelinePanel />}
      {view === "timeline" && <TimelinePanel />}
    </div>
  );
}
