"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { JobDTO } from "@/lib/api";

interface DisplayJob {
  id: string;
  sample_id: string;
  status: string;
  created_at: string;
  duration: string | null;
}

function mapJob(j: JobDTO): DisplayJob {
  let duration: string | null = null;
  if (j.duration_seconds) {
    const m = Math.floor(j.duration_seconds / 60);
    const s = Math.round(j.duration_seconds % 60);
    duration = `${m}m ${String(s).padStart(2, "0")}s`;
  }
  return {
    id: j.id,
    sample_id: j.sample_id,
    status: j.status,
    created_at: j.created_at,
    duration,
  };
}

const STATUS_BADGE: Record<string, { class: string; dot: string }> = {
  completed: { class: "text-status-green", dot: "bg-status-green" },
  running: { class: "text-status-blue", dot: "bg-status-blue" },
  pending: { class: "text-text-muted", dot: "bg-text-muted" },
  failed: { class: "text-status-red", dot: "bg-status-red" },
  cancelled: { class: "text-text-muted", dot: "bg-text-muted" },
};

const FILTERS = ["all", "completed", "running", "pending", "failed", "cancelled"];

const MOCK_JOBS: DisplayJob[] = [
  { id: "j-001", sample_id: "s-001", status: "completed", created_at: new Date(Date.now() - 3600000).toISOString(), duration: "4m 12s" },
  { id: "j-002", sample_id: "s-002", status: "running", created_at: new Date(Date.now() - 600000).toISOString(), duration: null },
  { id: "j-003", sample_id: "s-003", status: "completed", created_at: new Date(Date.now() - 7200000).toISOString(), duration: "3m 48s" },
  { id: "j-004", sample_id: "s-004", status: "failed", created_at: new Date(Date.now() - 10800000).toISOString(), duration: "0m 15s" },
  { id: "j-005", sample_id: "s-005", status: "completed", created_at: new Date(Date.now() - 14400000).toISOString(), duration: "5m 02s" },
  { id: "j-006", sample_id: "s-006", status: "pending", created_at: new Date(Date.now() - 300000).toISOString(), duration: null },
];

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

function countByStatus(jobs: DisplayJob[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const j of jobs) {
    counts[j.status] = (counts[j.status] || 0) + 1;
  }
  return counts;
}

export default function JobsPage() {
  const [filter, setFilter] = useState("all");
  const [jobs, setJobs] = useState<DisplayJob[]>(MOCK_JOBS);
  const [apiAvailable, setApiAvailable] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const res = await api.getJobs(1, 100);
        setJobs(res.items.map(mapJob));
        setApiAvailable(true);
      } catch {
        /* use mock data */
      }
    })();
  }, []);

  const counts = countByStatus(jobs);
  const filtered = filter === "all" ? jobs : jobs.filter((j) => j.status === filter);

  return (
    <div>
      {!apiAvailable && (
        <div className="mb-4 p-2.5 text-xs text-status-orange bg-status-orange/10 border border-status-orange/20 rounded">
          API not available. Showing demo data.
        </div>
      )}

      <div className="flex gap-6">
        {/* Filter Sidebar */}
        <div className="w-48 shrink-0">
          <div className="bg-bg-surface border border-border rounded p-3">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-xs font-medium text-text-primary uppercase tracking-wider">Filters</h3>
              {filter !== "all" && (
                <button
                  onClick={() => setFilter("all")}
                  className="text-xs text-accent hover:underline"
                >
                  Clear
                </button>
              )}
            </div>
            <p className="text-xs text-text-muted mb-2 uppercase tracking-wider">Status</p>
            <div className="space-y-1">
              {FILTERS.map((f) => {
                const active = filter === f;
                const count = f === "all" ? jobs.length : counts[f] || 0;
                return (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    className={`w-full flex items-center justify-between px-2 py-1.5 rounded text-xs transition-colors ${
                      active
                        ? "bg-bg-active text-text-primary"
                        : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      {f !== "all" && (
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${STATUS_BADGE[f]?.dot || "bg-text-muted"}`}
                        />
                      )}
                      <span className="capitalize">{f}</span>
                    </div>
                    <span className="text-text-muted">{count}</span>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Job List */}
        <div className="flex-1 bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Analysis Jobs &mdash; {filtered.length} results
            </h2>
          </div>
          <div className="divide-y divide-border-light">
            {filtered.map((job) => {
              const badge = STATUS_BADGE[job.status] || STATUS_BADGE.pending;
              return (
                <Link
                  key={job.id}
                  href={`/analysis/${job.id}`}
                  className="flex items-center justify-between px-4 py-3 hover:bg-bg-hover transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <svg
                      width="14" height="14" viewBox="0 0 24 24" fill="none"
                      stroke="var(--text-secondary)" strokeWidth="1.5"
                    >
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
                      <path d="M14 2v6h6" />
                    </svg>
                    <div>
                      <p className="text-sm text-text-primary">{job.sample_id.slice(0, 12)}</p>
                      <p className="text-xs text-text-muted">{timeAgo(job.created_at)}{job.duration ? ` / ${job.duration}` : ""}</p>
                    </div>
                  </div>
                  <div className={`flex items-center gap-1.5 ${badge.class}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${badge.dot}`} />
                    <span className="text-xs font-medium uppercase tracking-wider">
                      {job.status}
                    </span>
                  </div>
                </Link>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
