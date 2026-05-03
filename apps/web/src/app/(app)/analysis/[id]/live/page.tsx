"use client";

import { useState, useEffect } from "react";
import { useParams } from "next/navigation";

interface AgentState {
  name: string;
  status: "idle" | "analyzing" | "done";
  verdict?: string;
  confidence?: number;
  lastMessage?: string;
}

interface EventLog {
  time: string;
  type: string;
  message: string;
}

const STATUS_STYLES: Record<string, { dot: string; text: string }> = {
  idle: { dot: "bg-text-muted", text: "text-text-muted" },
  analyzing: { dot: "bg-status-blue", text: "text-status-blue" },
  done: { dot: "bg-status-green", text: "text-status-green" },
};

const INITIAL_AGENTS: AgentState[] = [
  { name: "Static Analyst", status: "idle" },
  { name: "Dynamic Analyst", status: "idle" },
  { name: "Network Analyst", status: "idle" },
  { name: "Code Analyst", status: "idle" },
  { name: "Threat Intel Analyst", status: "idle" },
];

/* Simulate live analysis progression for demo */
function useSimulatedAnalysis() {
  const [agents, setAgents] = useState<AgentState[]>(INITIAL_AGENTS);
  const [events, setEvents] = useState<EventLog[]>([]);
  const [complete, setComplete] = useState(false);

  useEffect(() => {
    const steps = [
      { delay: 1000, agent: 0, status: "analyzing" as const, msg: "Static analysis started" },
      { delay: 2500, agent: 1, status: "analyzing" as const, msg: "Dynamic sandbox initialized" },
      { delay: 3500, agent: 4, status: "analyzing" as const, msg: "Querying threat intelligence databases" },
      { delay: 5000, agent: 0, status: "done" as const, verdict: "malicious", confidence: 85, msg: "Static analysis complete: packed PE with high entropy" },
      { delay: 6500, agent: 2, status: "analyzing" as const, msg: "Capturing network traffic" },
      { delay: 7000, agent: 3, status: "analyzing" as const, msg: "Decompiling binary for code analysis" },
      { delay: 8000, agent: 4, status: "done" as const, verdict: "malicious", confidence: 88, msg: "Threat Intel: matches known Emotet campaign" },
      { delay: 10000, agent: 1, status: "done" as const, verdict: "malicious", confidence: 80, msg: "Dynamic analysis: process injection detected" },
      { delay: 12000, agent: 2, status: "done" as const, verdict: "malicious", confidence: 82, msg: "Network: C2 beaconing to known infrastructure" },
      { delay: 14000, agent: 3, status: "done" as const, verdict: "suspicious", confidence: 72, msg: "Code analysis: obfuscated API resolution chains" },
      { delay: 15000, agent: -1, status: "done" as const, msg: "Analysis complete. Final verdict: Malicious (87/100)" },
    ];

    const timers = steps.map((step) =>
      setTimeout(() => {
        const now = new Date().toLocaleTimeString();
        setEvents((prev) => [
          { time: now, type: step.status, message: step.msg },
          ...prev,
        ]);

        if (step.agent >= 0) {
          setAgents((prev) =>
            prev.map((a, i) =>
              i === step.agent
                ? {
                    ...a,
                    status: step.status,
                    verdict: step.verdict || a.verdict,
                    confidence: step.confidence || a.confidence,
                    lastMessage: step.msg,
                  }
                : a
            )
          );
        } else {
          setComplete(true);
        }
      }, step.delay)
    );

    return () => timers.forEach(clearTimeout);
  }, []);

  return { agents, events, complete };
}

export default function LiveAnalysisPage() {
  const params = useParams();
  const { agents, events, complete } = useSimulatedAnalysis();

  const VERDICT_COLORS: Record<string, string> = {
    malicious: "text-status-red",
    suspicious: "text-status-orange",
    benign: "text-status-green",
  };

  return (
    <div className="space-y-4">
      {/* Status Banner */}
      <div
        className={`p-3 rounded border text-xs font-medium ${
          complete
            ? "bg-status-green/10 border-status-green/20 text-status-green"
            : "bg-status-blue/10 border-status-blue/20 text-status-blue"
        }`}
      >
        {complete
          ? "Analysis complete. View full results in the Summary tab."
          : `Live analysis in progress for job ${params.id}...`}
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Agent Cards */}
        <div className="col-span-2 space-y-2">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider mb-2">
            Agent Status
          </h2>
          <div className="grid grid-cols-2 gap-2">
            {agents.map((agent) => {
              const style = STATUS_STYLES[agent.status];
              return (
                <div
                  key={agent.name}
                  className="bg-bg-surface border border-border rounded p-3"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium text-text-primary">
                      {agent.name}
                    </span>
                    <div className={`flex items-center gap-1.5 ${style.text}`}>
                      <span
                        className={`w-1.5 h-1.5 rounded-full ${style.dot} ${
                          agent.status === "analyzing" ? "animate-pulse" : ""
                        }`}
                      />
                      <span className="text-xs capitalize">{agent.status}</span>
                    </div>
                  </div>
                  {agent.verdict && (
                    <div className="flex items-center gap-2 mb-1">
                      <span
                        className={`text-xs capitalize ${VERDICT_COLORS[agent.verdict] || "text-text-muted"}`}
                      >
                        {agent.verdict}
                      </span>
                      <span className="text-xs text-text-muted font-mono">
                        {agent.confidence}%
                      </span>
                    </div>
                  )}
                  {agent.lastMessage && (
                    <p className="text-xs text-text-muted mt-1 truncate">
                      {agent.lastMessage}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Event Log */}
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-3 py-2.5 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Event Log
            </h2>
          </div>
          <div className="h-80 overflow-y-auto">
            {events.map((evt, i) => (
              <div
                key={i}
                className="px-3 py-2 border-b border-border-light text-xs hover:bg-bg-hover"
              >
                <span className="text-text-muted font-mono mr-2">
                  {evt.time}
                </span>
                <span className="text-text-secondary">{evt.message}</span>
              </div>
            ))}
            {events.length === 0 && (
              <div className="p-4 text-xs text-text-muted text-center">
                Waiting for events...
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
