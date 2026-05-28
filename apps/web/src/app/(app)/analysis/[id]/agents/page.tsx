"use client";

import { useReport } from "../layout";
import type { AgentFindingStatus } from "@/types";

const VERDICT_STYLES: Record<string, { icon: string; class: string }> = {
  malicious: { icon: "\u2716", class: "text-status-red" },
  suspicious: { icon: "?", class: "text-status-orange" },
  benign: { icon: "\u2714", class: "text-status-green" },
  unknown: { icon: "-", class: "text-text-muted" },
};

/* D15+D16: status badge styling. The status comes from the worker and
 * is the source of truth for whether the analyst produced anything
 * meaningful \u2014 verdict + confidence remain useful only when
 * status === "complete". */
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

function confidenceToVerdict(confidence: number): string {
  if (confidence >= 75) return "malicious";
  if (confidence >= 45) return "suspicious";
  return "benign";
}

export default function AgentsTab() {
  const { report, job, loading } = useReport();

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
    // Verdict only makes sense for completed runs. For failed / timed-out
    // / no-data the lifecycle status is the entire story; suppress the
    // misleading derived verdict label.
    const verdict = status === "complete" ? confidenceToVerdict(pct) : "unknown";
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
      name: f.agent_name,
      verdict,
      confidence: pct,
      domain: f.domain,
      key_finding: keyFinding,
      revision_rounds: f.revision_rounds,
      status,
    };
  });

  const maliciousCount = agents.filter(
    (a) => a.status === "complete" && a.verdict === "malicious",
  ).length;
  const completedCount = agents.filter((a) => a.status === "complete").length;

  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          Agent Detection Results
        </h2>
        <span className="text-xs text-text-muted">
          {agents.length > 0
            ? `${maliciousCount}/${completedCount} flagged as malicious${
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
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-28">Verdict</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-24">Confidence</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-16">Rounds</th>
              <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider">Key Finding</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-light">
            {agents.map((agent) => {
              const style = VERDICT_STYLES[agent.verdict] || VERDICT_STYLES.unknown;
              return (
                <tr key={agent.name} className="hover:bg-bg-hover transition-colors">
                  <td className="px-4 py-3">
                    <span className="text-sm text-text-primary">{agent.name}</span>
                    {agent.domain && (
                      <span className="block text-xs text-text-muted">{agent.domain}</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {agent.status === "complete" ? (
                      <div className={`flex items-center gap-1.5 ${style.class}`}>
                        <span className="text-sm">{style.icon}</span>
                        <span className="text-xs font-medium capitalize">{agent.verdict}</span>
                      </div>
                    ) : (
                      <span
                        className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded font-mono ${STATUS_STYLES[agent.status].bg} ${STATUS_STYLES[agent.status].text}`}
                      >
                        {STATUS_STYLES[agent.status].label}
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
        </table>
      )}
    </div>
  );
}
