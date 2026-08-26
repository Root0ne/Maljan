"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "next/navigation";
import { useWebSocket } from "@/lib/useWebSocket";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { verdictLabel } from "@/lib/verdict";
import { messagesFromEvents } from "@/lib/transcript";
import TranscriptPanel from "@/components/TranscriptPanel";
import type { WSEvent } from "@/types";

type AgentPhase = "waiting" | "analyzing" | "done";
type PipelinePhase = "waiting" | "analyzing" | "negotiation" | "completed" | "failed";

interface AgentState {
  name: string;
  phase: AgentPhase;
}

interface EventEntry {
  ts: string;
  type: string;
  message: string;
}

function buildMessage(type: string, data: Record<string, unknown>): string {
  switch (type) {
    case "status_change":
      return `Job status changed to: ${data.status}`;
    case "pipeline_started": {
      const agents = data.agents as string[] | undefined;
      return `Pipeline started — ${agents?.length ?? 0} analysts queued`;
    }
    case "agent_progress":
      return `Agent [${data.agent}]: ${data.phase}`;
    case "agent_message": {
      const claims = Array.isArray(data.claims) ? data.claims.length : 0;
      return `${data.speaker} (${data.role}): ${data.status}${claims ? `, ${claims} claim(s)` : ""}`;
    }
    case "phase_change":
      return `Pipeline phase: ${data.phase}`;
    case "completed":
      // audit 2026-07-26 (T2): the WS payload carries the raw backend verdict
      // ("Malware"); show the same normalised label as every other surface.
      return `Analysis complete — verdict: ${verdictLabel(String(data.verdict ?? ""))} (confidence: ${data.confidence})`;
    case "error":
      return `Error: ${String(data.error ?? "unknown error")}`;
    case "cancelled":
      return "Job was cancelled.";
    default:
      return type;
  }
}

const PHASE_CONFIG: Record<PipelinePhase, { banner: string; label: string }> = {
  waiting: {
    banner: "bg-text-muted/10 border-text-muted/20 text-text-muted",
    label: "Waiting for worker to pick up job...",
  },
  analyzing: {
    banner: "bg-status-blue/10 border-status-blue/20 text-status-blue",
    // audit 2026-07-26 (T1): the old copy claimed the analysts run in
    // parallel, but `parallel_analysts=False` is the default — they run one
    // after another. Keep the label topology-neutral so it stays true under
    // either setting.
    label: "Analyst agents examining the sample...",
  },
  negotiation: {
    banner: "bg-status-orange/10 border-status-orange/20 text-status-orange",
    label: "Negotiation phase: agents building consensus...",
  },
  completed: {
    banner: "bg-status-green/10 border-status-green/20 text-status-green",
    label: "Analysis complete. View full results in the Summary tab.",
  },
  failed: {
    banner: "bg-status-red/10 border-status-red/20 text-status-red",
    label: "Analysis failed. See event log for details.",
  },
};

const AGENT_PHASE_STYLES: Record<AgentPhase, { dot: string; text: string; label: string }> = {
  waiting: { dot: "bg-text-muted", text: "text-text-muted", label: "Waiting" },
  analyzing: { dot: "bg-status-blue animate-pulse", text: "text-status-blue", label: "Analyzing" },
  done: { dot: "bg-status-green", text: "text-status-green", label: "Done" },
};

interface PipelineEvent {
  type: string;
  data?: Record<string, unknown>;
  ts?: string;
}

export default function LiveAnalysisPage() {
  const params = useParams();
  const jobId = params.id as string;

  const { events: wsEvents, connected } = useWebSocket(jobId);

  const [agents, setAgents] = useState<AgentState[]>([]);
  const [messageEvents, setMessageEvents] = useState<WSEvent[]>([]);
  const [eventLog, setEventLog] = useState<EventEntry[]>([]);
  const [phase, setPhase] = useState<PipelinePhase>("waiting");
  const [jobMockMode, setJobMockMode] = useState<boolean | null>(null);
  // audit 2026-07-26 (§4 "sessizce yutulan hatalar"): the backfill, the job
  // fetch and the polling fallback all failed silently, so a page that had
  // quietly stopped tracking the run looked identical to a healthy one.
  const [feedError, setFeedError] = useState<string | null>(null);

  const processedCount = useRef(0);
  // Dedupe key set — covers both stream_id (from backfill) and a stable
  // composite key (type+ts+payload) for raw WS events that don't carry
  // a stream_id. Prevents double-counting when WS replays events that
  // arrived between the backfill request and subscription.
  const seenKeys = useRef<Set<string>>(new Set());

  /** Apply one pipeline event to local state. Idempotent via seenKeys. */
  const applyEvent = useCallback(
    (ev: PipelineEvent & { stream_id?: string }, _appendToEnd = false) => {
      const data = ev.data ?? {};
      const dedupeKey =
        ev.stream_id ?? `${ev.type}|${ev.ts ?? ""}|${JSON.stringify(data)}`;
      if (seenKeys.current.has(dedupeKey)) return;
      seenKeys.current.add(dedupeKey);

      const ts = ev.ts
        ? new Date(ev.ts).toLocaleTimeString()
        : new Date().toLocaleTimeString();

      // Skip heartbeats — don't clutter the log
      if (ev.type === "heartbeat" || ev.type === "pong") return;

      // Update pipeline state machine
      if (ev.type === "status_change" && data.status === "running") {
        setPhase("analyzing");
      }

      if (ev.type === "pipeline_started") {
        const agentNames = (data.agents as string[] | undefined) ?? [];
        setAgents(agentNames.map((name) => ({ name, phase: "waiting" })));
        setPhase("analyzing");
      }

      if (ev.type === "agent_progress") {
        const agentName = String(data.agent ?? "");
        const agentPhase = (data.phase as AgentPhase | undefined) ?? "analyzing";
        setAgents((prev) => {
          const exists = prev.some((a) => a.name === agentName);
          if (!exists) return [...prev, { name: agentName, phase: agentPhase }];
          return prev.map((a) =>
            a.name === agentName ? { ...a, phase: agentPhase } : a
          );
        });
      }

      // The transcript itself. Raw events are accumulated and normalised in
      // one place (lib/transcript) rather than reduced here, so this page and
      // the post-run PROCESS tab build their messages identically.
      if (ev.type === "agent_message") {
        setMessageEvents((prev) => [
          ...prev,
          { type: "agent_message", data, ts: ev.ts ?? new Date().toISOString() },
        ]);
        const speaker = String(data.speaker ?? "");
        const role = String(data.role ?? "");
        // An analyst that has spoken is finished — its own message is a more
        // reliable "done" signal than a separate progress event that may not
        // arrive if the node failed.
        if (speaker && (role === "analyst" || role === "reviser")) {
          setAgents((prev) =>
            prev.map((a) => (a.name === speaker ? { ...a, phase: "done" } : a))
          );
        }
      }

      if (ev.type === "phase_change") {
        const p = data.phase as string | undefined;
        if (p === "negotiation") setPhase("negotiation");
      }

      if (ev.type === "completed") {
        setPhase("completed");
        setAgents((prev) => prev.map((a) => ({ ...a, phase: "done" })));
      }

      if (ev.type === "error" || ev.type === "cancelled") {
        setPhase("failed");
      }

      const entry: EventEntry = { ts, type: ev.type, message: buildMessage(ev.type, data) };
      // Prepend so newest stays at the top, matching the WS-only ordering
      // the page already shipped with.
      setEventLog((prev) => [entry, ...prev]);
    },
    []
  );

  // One-shot backfill of historical events when the tab mounts mid-run
  // (audit 2026-05-17, LIVE-01). Events come back in chronological order
  // — feed them through ``applyEvent`` so the state machine and event
  // log replay the same way they would have if WS had been attached.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await api.getJobEvents(jobId);
        if (cancelled) return;
        for (const ev of res.events) {
          applyEvent(ev as PipelineEvent & { stream_id?: string });
        }
      } catch (err) {
        // The stream may legitimately not exist yet, but say so rather than
        // leaving an empty log that looks like "nothing has happened".
        if (!cancelled) {
          setFeedError(
            `Could not replay earlier events (${getErrorMessage(err)}). Only events received from now on are shown.`,
          );
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [jobId, applyEvent]);

  // Fetch the job once so we can surface whether THIS run was queued in
  // mock mode (audit 2026-05-17, W-01 follow-up). Mock verdicts must be
  // visually distinct from real ones; otherwise operators copy the
  // misleading "Malware 0.95" out of the UI into reports.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const job = await api.getJob(jobId);
        if (cancelled) return;
        const cfg = (job.config ?? {}) as Record<string, unknown>;
        setJobMockMode(Boolean(cfg.mock_mode));
      } catch (err) {
        // The MOCK badge is derived from this call — if it fails we cannot
        // promise the run is a real one, so surface it.
        if (!cancelled) {
          setFeedError(
            `Could not read this job's configuration (${getErrorMessage(err)}). The MOCK-mode badge may be missing.`,
          );
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [jobId]);

  // Process new WebSocket events as they arrive. ``applyEvent`` dedupes
  // against the backfill set so we never double-render an event.
  useEffect(() => {
    const newEvents = wsEvents.slice(processedCount.current);
    processedCount.current = wsEvents.length;
    for (const ev of newEvents) {
      applyEvent(ev as PipelineEvent);
    }
  }, [wsEvents, applyEvent]);

  // Polling fallback: catches completed/failed even if WS was disconnected
  useEffect(() => {
    if (phase === "completed" || phase === "failed") return;

    const interval = setInterval(async () => {
      try {
        const job = await api.getJob(jobId);
        if (job.status === "completed") {
          setPhase("completed");
          setAgents((prev) => prev.map((a) => ({ ...a, phase: "done" })));
        } else if (job.status === "failed") {
          setPhase("failed");
        }
        setFeedError(null);
      } catch (err) {
        setFeedError(
          `Status polling failed (${getErrorMessage(err)}). Live updates depend on the WebSocket alone until the API responds again.`,
        );
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [jobId, phase]);

  const phaseConfig = PHASE_CONFIG[phase];
  const transcript = useMemo(() => messagesFromEvents(messageEvents), [messageEvents]);
  const activeSpeaker = agents.find((a) => a.phase === "analyzing")?.name ?? null;

  return (
    <div className="space-y-4">
      {feedError && (
        <div
          role="alert"
          className="text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
        >
          {feedError}
        </div>
      )}

      {/* Status Banner */}
      <div
        className={`p-3 rounded border text-xs font-medium flex items-center justify-between ${phaseConfig.banner}`}
      >
        <span>{phaseConfig.label}</span>
        <span className="flex items-center gap-2 text-text-muted text-xs">
          {jobMockMode && (
            <span
              title="This run was submitted with mock_mode=true. Verdicts must not be trusted as production findings."
              className="rounded border border-status-red/40 bg-status-red/10 px-1.5 py-0.5 font-semibold text-status-red"
            >
              MOCK
            </span>
          )}
          <span className="flex items-center gap-1.5">
            <span
              className={`w-1.5 h-1.5 rounded-full ${connected ? "bg-status-green animate-pulse" : "bg-text-muted"}`}
            />
            {connected ? "Live" : "Reconnecting..."}
          </span>
        </span>
      </div>

      {/* The conversation itself, above the status grid and the raw log:
        * what the agents actually found is the reason to watch a live run,
        * and until now the page could only say that they were busy. */}
      <TranscriptPanel
        messages={transcript}
        live={phase === "analyzing" || phase === "negotiation"}
        activeSpeaker={activeSpeaker}
        /* This tab replays from the Redis event stream, which expires after
         * 24 h. An older run therefore has an empty feed here while its full
         * transcript is still on the PROCESS tab, rebuilt from the database —
         * say so rather than implying nothing was recorded. */
        emptyHint={
          phase === "completed" || phase === "failed"
            ? "The live event feed for this run has expired (events are kept for 24 hours). The full transcript is on the PROCESS tab."
            : undefined
        }
      />

      <div className="grid grid-cols-3 gap-4">
        {/* Agent Status Grid */}
        <div className="col-span-2 space-y-2">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider mb-2">
            Agent Status
          </h2>

          {agents.length === 0 ? (
            <div className="bg-bg-surface border border-border rounded p-8 text-center text-xs text-text-muted">
              {phase === "completed"
                ? "Analysis already completed. No live agents to display."
                : phase === "failed"
                ? "Analysis failed before any agent reported in. See Pipeline tab for details."
                : phase === "waiting"
                ? "Waiting for the worker to pick up this job…"
                : (
                  <span className="animate-pulse">Pipeline starting up — agent status will appear shortly.</span>
                )}
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-2">
              {agents.map((agent) => {
                const style = AGENT_PHASE_STYLES[agent.phase];
                const displayName = agent.name
                  .replace(/_/g, " ")
                  .replace(/\b\w/g, (c) => c.toUpperCase());
                return (
                  <div
                    key={agent.name}
                    className="bg-bg-surface border border-border rounded p-3"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-medium text-text-primary">{displayName}</span>
                      <div className={`flex items-center gap-1.5 ${style.text}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                        <span className="text-xs">{style.label}</span>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Event Log */}
        <div className="bg-bg-surface border border-border rounded flex flex-col">
          <div className="px-3 py-2.5 border-b border-border shrink-0">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Event Log
            </h2>
          </div>
          <div className="flex-1 overflow-y-auto h-72">
            {eventLog.map((evt, i) => (
              <div
                key={i}
                className="px-3 py-2 border-b border-border-light text-xs hover:bg-bg-hover"
              >
                <span className="text-text-muted font-mono mr-2 shrink-0">{evt.ts}</span>
                <span className="text-text-secondary">{evt.message}</span>
              </div>
            ))}
            {eventLog.length === 0 && (
              <div className="p-4 text-xs text-text-muted text-center">
                {phase === "completed" || phase === "failed"
                  ? "No live events were captured — pipeline finished before the page subscribed."
                  : (
                    <span className="animate-pulse">Waiting for events…</span>
                  )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
