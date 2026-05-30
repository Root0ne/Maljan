"use client";

import { useState, useEffect } from "react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";
import { api } from "@/lib/api";
import { useReport } from "../layout";

interface DebateEntry {
  round: number;
  agent: string;
  position: string;
  confidence: number;
  argument: string;
}

const AGENT_COLORS: Record<string, string> = {
  "Static Analyst": "#79c0ff",
  "Dynamic Analyst": "#ff7b72",
  "Network Analyst": "#ffa657",
  "Code Analyst": "#7ee787",
  "Threat Intel Analyst": "#d2a8ff",
};

const FALLBACK_COLOR = "#888888";

const POSITION_STYLES: Record<string, string> = {
  malicious: "text-status-red",
  suspicious: "text-status-orange",
  benign: "text-status-green",
};

function confidenceToPosition(confidence: number): string {
  if (confidence >= 75) return "malicious";
  if (confidence >= 45) return "suspicious";
  return "benign";
}

function parseNegotiationLog(negotiationLog: Record<string, unknown> | null | undefined): DebateEntry[] {
  if (!negotiationLog) return [];

  const entries: DebateEntry[] = [];

  // Try discussion_history array
  const discussion = negotiationLog.discussion_history as unknown[] | undefined;
  if (Array.isArray(discussion)) {
    discussion.forEach((item, i) => {
      if (!item || typeof item !== "object") return;
      const d = item as Record<string, unknown>;
      // confidence may be 0-1 (pipeline) or 0-100 (already scaled)
      let confidence = Number(d.confidence ?? d.final_confidence ?? 50);
      if (confidence <= 1 && confidence > 0) confidence = confidence * 100;
      entries.push({
        round: Number(d.round ?? Math.floor(i / 3) + 1),
        agent: String(d.agent ?? d.agent_name ?? "Unknown Agent"),
        position: String(d.position ?? d.verdict ?? confidenceToPosition(confidence)),
        confidence: Math.round(confidence),
        argument: String(d.argument ?? d.content ?? d.message ?? ""),
      });
    });
  }

  // Fallback: try negotiation_rounds
  const rounds = negotiationLog.negotiation_rounds as unknown[] | undefined;
  if (entries.length === 0 && Array.isArray(rounds)) {
    rounds.forEach((round, roundIdx) => {
      if (!round || typeof round !== "object") return;
      const r = round as Record<string, unknown>;
      const agentArgs = (r.arguments ?? r.agent_arguments ?? []) as unknown[];
      if (Array.isArray(agentArgs)) {
        agentArgs.forEach((arg) => {
          if (!arg || typeof arg !== "object") return;
          const a = arg as Record<string, unknown>;
          const confidence = Number(a.confidence ?? 50);
          entries.push({
            round: roundIdx + 1,
            agent: String(a.agent ?? a.agent_name ?? "Unknown Agent"),
            position: String(a.position ?? confidenceToPosition(confidence)),
            confidence,
            argument: String(a.argument ?? a.content ?? ""),
          });
        });
      }
    });
  }

  return entries;
}

export default function TimelineTab() {
  const { report, job, loading } = useReport();
  const [timelineData, setTimelineData] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    if (report?.id) {
      api.getReportTimeline(report.id)
        .then((data) => setTimelineData(data))
        .catch(() => {});
    }
  }, [report?.id]);

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

  const negotiationLog = timelineData ?? (report?.negotiation_log as Record<string, unknown> | null | undefined);
  const debateEntries = parseNegotiationLog(negotiationLog);

  // Also use agent_findings as a fallback for the timeline (one entry per agent)
  const agentFallbackEntries: DebateEntry[] = debateEntries.length === 0
    ? (report?.agent_findings ?? []).map((f) => ({
        round: 1,
        agent: f.agent_name,
        position: confidenceToPosition(Math.round(f.final_confidence * 100)),
        confidence: Math.round(f.final_confidence * 100),
        argument: `Agent completed analysis with ${f.revision_rounds} revision round(s). ${f.claims?.length ?? 0} claims recorded.`,
      }))
    : [];

  const allEntries = debateEntries.length > 0 ? debateEntries : agentFallbackEntries;

  // Build chart data
  const rounds = [...new Set(allEntries.map((r) => r.round))].sort((a, b) => a - b);
  const agents = [...new Set(allEntries.map((r) => r.agent))];
  const chartData = rounds.map((round) => {
    const entry: Record<string, number> = { round };
    for (const a of agents) {
      const r = allEntries.find((x) => x.round === round && x.agent === a);
      if (r) entry[a] = r.confidence;
    }
    return entry;
  });

  if (allEntries.length === 0) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        {report
          ? "No negotiation timeline data was recorded for this analysis."
          : "Analysis has not completed yet."}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Confidence Convergence Chart */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Confidence Convergence
          </h2>
        </div>
        <div className="p-4">
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={chartData}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis
                dataKey="round"
                tick={{ fill: "var(--text-muted)", fontSize: 12 }}
                axisLine={{ stroke: "var(--border)" }}
                tickLine={false}
                label={{
                  value: "Round",
                  position: "insideBottomRight",
                  offset: -5,
                  fill: "var(--text-muted)",
                  fontSize: 12,
                }}
              />
              <YAxis
                domain={[0, 100]}
                tick={{ fill: "var(--text-muted)", fontSize: 12 }}
                axisLine={{ stroke: "var(--border)" }}
                tickLine={false}
                label={{
                  value: "Confidence %",
                  angle: -90,
                  position: "insideLeft",
                  fill: "var(--text-muted)",
                  fontSize: 12,
                }}
              />
              <Tooltip
                contentStyle={{
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--border)",
                  borderRadius: "4px",
                  fontSize: "12px",
                  color: "var(--text-primary)",
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: "12px" }}
                formatter={(value: string) => (
                  <span style={{ color: "var(--text-secondary)" }}>{value}</span>
                )}
              />
              {agents.map((agent) => (
                <Line
                  key={agent}
                  type="monotone"
                  dataKey={agent}
                  stroke={AGENT_COLORS[agent] ?? FALLBACK_COLOR}
                  strokeWidth={1.5}
                  dot={{ fill: AGENT_COLORS[agent] ?? FALLBACK_COLOR, r: 3 }}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Debate Timeline */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Negotiation Debate
          </h2>
          <span className="text-xs text-text-muted">
            {allEntries.length} entries across {rounds.length} round(s)
          </span>
        </div>
        <div className="divide-y divide-border-light">
          {allEntries.map((entry, i) => (
            <div key={i} className="flex gap-4 px-4 py-3 hover:bg-bg-hover transition-colors">
              <div className="flex flex-col items-center shrink-0 w-12">
                <span className="text-xs text-text-muted">R{entry.round}</span>
                <div
                  className="w-2 h-2 rounded-full mt-1"
                  style={{ backgroundColor: AGENT_COLORS[entry.agent] ?? FALLBACK_COLOR }}
                />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className="text-xs font-medium"
                    style={{ color: AGENT_COLORS[entry.agent] ?? FALLBACK_COLOR }}
                  >
                    {entry.agent}
                  </span>
                  <span className={`text-xs capitalize ${POSITION_STYLES[entry.position] || "text-text-muted"}`}>
                    {entry.position}
                  </span>
                  <span className="text-xs text-text-muted font-mono">
                    {entry.confidence}%
                  </span>
                </div>
                {entry.argument && (
                  <p className="text-sm text-text-secondary leading-relaxed">
                    {entry.argument}
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
