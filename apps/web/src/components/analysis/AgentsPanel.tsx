"use client";

import { useReport } from "@/app/(app)/analysis/[id]/layout";
import { rosterNames } from "@/lib/rosterNames";
import type { AgentFindingStatus, JobRoster } from "@/types";

/* Per-agent confidence tier. IMPORTANT: ``final_confidence`` is each agent's
 * confidence in its OWN claim \u2014 NOT a probability of maliciousness. A benign
 * finding ("no malicious behavior") can legitimately carry 100% confidence, so
 * this must never be rendered as a malicious/suspicious/benign verdict (that
 * produced the "Malicious \u00b7 100% \u00b7 no malicious behavior" contradiction). We
 * surface it as a neutral signal strength; the agent's actual stance lives in
 * the Key Finding column. */
const SIGNAL_STYLES: Record<string, { icon: string; class: string }> = {
  high: { icon: "\u25cf", class: "text-text-primary" },
  medium: { icon: "\u25d0", class: "text-text-secondary" },
  low: { icon: "\u25cb", class: "text-text-muted" },
  unknown: { icon: "-", class: "text-text-muted" },
};

/* The status badge. The status comes from the worker and is the source of
 * truth for whether the analyst produced anything meaningful \u2014 the verdict
 * and the confidence are useful only when it is "complete". */
const STATUS_STYLES: Record<
  AgentFindingStatus,
  { label: string; bg: string; text: string }
> = {
  complete: {
    label: "complete",
    bg: "bg-status-green/10",
    text: "text-status-green",
  },
  no_data: {
    label: "no data",
    bg: "bg-text-muted/10",
    text: "text-text-muted",
  },
  /* The analyst had data and read it, and its model stopped before writing a
     report \u2014 a different fact from having nothing to read. */
  no_claims: {
    label: "no report",
    bg: "bg-status-orange/10",
    text: "text-status-orange",
  },
  failed: {
    label: "failed",
    bg: "bg-status-red/10",
    text: "text-status-red",
  },
  timeout: {
    label: "timed out",
    bg: "bg-status-orange/10",
    text: "text-status-orange",
  },
};

function confidenceToSignal(confidence: number): string {
  if (confidence >= 75) return "high";
  if (confidence >= 45) return "medium";
  return "low";
}

/* What each agent concluded. How much work it did is one line up, on the
 * participants strip, and is not restated here: the same number in two places
 * on one screen is the thing this view was built to remove.
 *
 * The names are the run's roster, read through the selector the strip above
 * and the conversation beside it read: an agent an operator called "Ahmet" is
 * "Ahmet" here too, rather than the `ahmet_1` the pipeline keys it by. A run
 * whose roster names nobody shows the key, which is all it has. */
export default function AgentsTab({ roster = null }: { roster?: JobRoster | null }) {
  const { report, job, loading } = useReport();
  const names = rosterNames(roster);

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  if (!report && (!job || job.status !== "completed")) {
    return (
      <div className="p-4 text-sm text-text-secondary animate-pulse">
        Analysis in progress...
      </div>
    );
  }

  const agents = (report?.agent_findings ?? []).map((f) => {
    const pct = Math.round(f.final_confidence * 100);
    const status: AgentFindingStatus = (f.status ?? "complete") as AgentFindingStatus;
    // Signal strength only makes sense for completed runs. For failed /
    // timed-out / no-data the lifecycle status is the entire story.
    const signal = status === "complete" ? confidenceToSignal(pct) : "unknown";
    // Extract first claim description as key finding
    let keyFinding = "No specific findings recorded.";
    if (f.claims && Array.isArray(f.claims) && f.claims.length > 0) {
      const first = f.claims[0];
      if (first && typeof first === "object" && "description" in first) {
        keyFinding = String((first as Record<string, unknown>).description);
      } else if (first && typeof first === "object" && "claim" in first) {
        keyFinding = String((first as Record<string, unknown>).claim);
      } else if (typeof first === "string") {
        keyFinding = first;
      }
    }
    // Prefer the status_reason for non-complete rows so the table
    // explains the gap instead of repeating "No specific findings".
    if (status !== "complete" && f.status_reason) {
      keyFinding = String(f.status_reason);
    }
    return {
      key: f.agent_name,
      name: names.agent(f.agent_name),
      signal,
      confidence: pct,
      domain: f.domain,
      key_finding: keyFinding,
      revision_rounds: f.revision_rounds,
      status,
    };
  });

  const completedCount = agents.filter((a) => a.status === "complete").length;

  // Which stage ran each agent, from the run's own stage rollup. An agent the
  // rollup does not mention is grouped on its own rather than filed under a
  // stage it may not have been in.
  const stages = report?.run_summary?.stages ?? [];
  const stageOf = (key: string) =>
    stages.find((stage) => (stage.agents ?? []).includes(key))?.key ?? "";
  const groups: Array<{ stage: string; rows: typeof agents }> = [];
  for (const agent of agents) {
    const key = stageOf(agent.key);
    const group = groups.find((g) => g.stage === key);
    if (group) group.rows.push(agent);
    else groups.push({ stage: key, rows: [agent] });
  }

  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          Agent Detection Results
        </h2>
        <span className="text-xs text-text-muted">
          {agents.length > 0
            ? `${completedCount}/${agents.length} agent${
                agents.length === 1 ? "" : "s"
              } completed${
                completedCount < agents.length
                  ? ` (${agents.length - completedCount} non-complete)`
                  : ""
              }`
            : "No agent data"}
        </span>
      </div>

      {agents.length === 0 ? (
        <div className="p-8 text-center text-sm text-text-secondary">
          {report ? "No agent findings recorded for this analysis." : "Analysis has not completed yet."}
        </div>
      ) : (
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-44">Agent</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-28">Signal</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-24">Confidence</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-16">Rounds</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider">Key Finding</th>
            </tr>
          </thead>
          {groups.map((group) => (
          <tbody key={group.stage || "__ungrouped"} className="divide-y divide-border-light">
            {group.stage && (
              <tr className="bg-bg-deep">
                <td colSpan={5} className="px-4 py-1.5">
                  <span className="text-[10px] uppercase tracking-wider text-text-muted">
                    stage {names.stage(group.stage)}
                  </span>
                </td>
              </tr>
            )}
            {group.rows.map((agent) => {
              const style = SIGNAL_STYLES[agent.signal] || SIGNAL_STYLES.unknown;
              return (
                <tr key={agent.key} className="hover:bg-bg-hover">
                  <td className="px-4 py-3">
                    <span className="text-sm text-text-primary">{agent.name}</span>
                    {agent.domain && (
                      <span className="block text-xs text-text-muted">{agent.domain}</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {agent.status === "complete" ? (
                      <div className={`flex items-center gap-1.5 ${style.class}`}>
                        <span className="text-sm" aria-hidden="true">{style.icon}</span>
                        <span className="text-xs font-medium capitalize">{agent.signal}</span>
                      </div>
                    ) : (
                      // Falls back to the `no_data` style if the backend ever
                      // emits a status outside the known union, which would
                      // otherwise read `.bg` off `undefined`.
                      <span
                        className={`text-[11px] uppercase tracking-wider px-1.5 py-0.5 rounded font-mono ${(STATUS_STYLES[agent.status] ?? STATUS_STYLES.no_data).bg} ${(STATUS_STYLES[agent.status] ?? STATUS_STYLES.no_data).text}`}
                      >
                        {(STATUS_STYLES[agent.status] ?? STATUS_STYLES.no_data).label}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {agent.status === "complete" ? (
                      <div className="flex items-center gap-2">
                        <div className="w-12 h-1.5 bg-bg-deep rounded-sm overflow-hidden">
                          <div
                            className="h-full rounded-sm"
                            style={{
                              width: `${agent.confidence}%`,
                              backgroundColor:
                                agent.confidence >= 75
                                  ? "var(--status-red)"
                                  : agent.confidence >= 45
                                  ? "var(--status-orange)"
                                  : "var(--status-green)",
                              opacity: 0.7,
                            }}
                          />
                        </div>
                        <span className="text-xs text-text-secondary font-mono">
                          {agent.confidence}%
                        </span>
                      </div>
                    ) : (
                      <span className="text-xs text-text-muted">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-text-muted font-mono">{agent.revision_rounds}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-text-secondary" title={agent.key_finding}>
                      {agent.key_finding.length > 120
                        ? agent.key_finding.slice(0, 117) + "..."
                        : agent.key_finding}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
          ))}
        </table>
      )}
    </div>
  );
}
