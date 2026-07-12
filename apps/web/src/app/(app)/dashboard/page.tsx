"use client";

import { getErrorMessage } from "@/lib/errors";
import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { DashboardStatsDTO, JobDTO, SystemStatusDTO } from "@/lib/api";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";

interface DisplayStats {
  total_jobs: number;
  total_samples: number;
  completed: number;
  running: number;
  failed: number;
  malicious_count: number;
  suspicious_count: number;
  benign_count: number;
  avg_duration_seconds: number;
}

const VERDICT_COLORS: Record<string, string> = {
  malicious: "var(--status-red)",
  suspicious: "var(--status-orange)",
  benign: "var(--status-green)",
};

const STATUS_STYLES: Record<string, string> = {
  completed: "text-status-green",
  running: "text-status-blue",
  pending: "text-text-muted",
  failed: "text-status-red",
  cancelled: "text-text-muted",
};

function StatCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: string | number;
  sub?: string;
}) {
  return (
    <div className="bg-bg-surface border border-border rounded p-4">
      <p className="text-xs text-text-secondary uppercase tracking-wider mb-1">
        {label}
      </p>
      <p className="text-2xl font-semibold text-text-primary">{value}</p>
      {sub && <p className="text-xs text-text-muted mt-1">{sub}</p>}
    </div>
  );
}

function StatCardSkeleton() {
  return (
    <div className="bg-bg-surface border border-border rounded p-4 animate-pulse">
      <div className="h-3 w-24 bg-bg-active rounded mb-2" />
      <div className="h-8 w-16 bg-bg-active rounded" />
    </div>
  );
}

function formatDuration(seconds: number | null): string {
  if (seconds === null || seconds === 0) return "N/A";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function mapApiStats(s: DashboardStatsDTO): DisplayStats {
  const byStatus = s.jobs_by_status || {};
  const byVerdict = s.verdict_distribution || {};

  // The API returns the MalwareReport verdict casing ("Malware", "Suspicious",
  // "Benign") plus legacy "malicious" from older rows. Build a canonical
  // lookup keyed by lowercase so any combination resolves correctly. Without
  // this, the chart silently shows "no data" even when the API reports counts.
  const verdictLookup: Record<string, number> = {};
  for (const [key, value] of Object.entries(byVerdict)) {
    verdictLookup[key.toLowerCase()] = (verdictLookup[key.toLowerCase()] || 0) + (value || 0);
  }

  return {
    total_jobs: s.total_jobs,
    total_samples: s.total_samples,
    completed: byStatus["completed"] || 0,
    running: byStatus["running"] || 0,
    failed: byStatus["failed"] || 0,
    // "Malware" (canonical) and "malicious" (legacy) both count as malicious.
    malicious_count: (verdictLookup["malware"] || 0) + (verdictLookup["malicious"] || 0),
    suspicious_count: verdictLookup["suspicious"] || 0,
    benign_count: verdictLookup["benign"] || 0,
    avg_duration_seconds: s.avg_duration_seconds || 0,
  };
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DisplayStats | null>(null);
  const [jobs, setJobs] = useState<JobDTO[]>([]);
  const [systemStatus, setSystemStatus] = useState<SystemStatusDTO | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const [s, j, sys] = await Promise.all([
          api.getDashboardStats(),
          api.getJobs(1, 10),
          // System status is best-effort: failure here must not block the
          // rest of the dashboard from rendering.
          api.getSystemStatus().catch(() => null),
        ]);
        setStats(mapApiStats(s));
        setJobs(j.items.slice(0, 10));
        setSystemStatus(sys);
      } catch (err) {
        setError(getErrorMessage(err) || "Failed to load dashboard data.");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  if (loading) {
    return (
      <div>
        <div className="grid grid-cols-4 gap-4 mb-6">
          <StatCardSkeleton />
          <StatCardSkeleton />
          <StatCardSkeleton />
          <StatCardSkeleton />
        </div>
        <div className="grid grid-cols-3 gap-4">
          <div className="col-span-2 bg-bg-surface border border-border rounded animate-pulse">
            <div className="h-10 border-b border-border" />
            <div className="p-4 space-y-3">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="h-8 bg-bg-active rounded" />
              ))}
            </div>
          </div>
          <div className="bg-bg-surface border border-border rounded animate-pulse">
            <div className="h-10 border-b border-border" />
            <div className="p-4">
              <div className="h-44 bg-bg-active rounded" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 text-sm text-status-red bg-status-red/10 border border-status-red/20 rounded">
        {error}
      </div>
    );
  }

  const verdictData = stats
    ? [
        { name: "Malicious", value: stats.malicious_count },
        { name: "Suspicious", value: stats.suspicious_count },
        { name: "Benign", value: stats.benign_count },
      ].filter((d) => d.value > 0)
    : [];

  const verdictColors = [
    VERDICT_COLORS.malicious,
    VERDICT_COLORS.suspicious,
    VERDICT_COLORS.benign,
  ];

  return (
    <div>
      {/* Mock-mode banner (audit 2026-05-17, W-01 follow-up): operators
          frequently miss the worker log line announcing mock mode. Red
          banner makes the configuration impossible to overlook. */}
      {systemStatus?.mock_mode_allowed && (
        <div
          role="alert"
          className="mb-4 flex items-start gap-3 rounded border border-status-red/40 bg-status-red/10 p-3 text-sm"
        >
          <span className="font-semibold text-status-red">MOCK MODE ALLOWED</span>
          <span className="text-text-secondary">
            The worker accepts <code>MALJAN_MOCK_MODE=true</code> or per-job
            <code> config.mock_mode=true</code> and may short-circuit the
            real pipeline. Verdicts produced under this gate must not be
            treated as production findings. Unset
            <code> MOCK_MODE_ALLOWED</code> and restart the API to disable.
          </span>
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Analyses" value={stats?.total_jobs ?? 0} />
        <StatCard
          label="Completed"
          value={stats?.completed ?? 0}
          sub={`${stats?.running ?? 0} running`}
        />
        <StatCard
          label="Failed"
          value={stats?.failed ?? 0}
          sub={`${(((stats?.failed ?? 0) / Math.max(stats?.total_jobs ?? 1, 1)) * 100).toFixed(1)}% failure rate`}
        />
        <StatCard
          label="Avg Duration"
          value={formatDuration(stats?.avg_duration_seconds ?? null)}
        />
      </div>

      <div className="grid grid-cols-3 gap-4">
        {/* Recent Analyses */}
        <div className="col-span-2 bg-bg-surface border border-border rounded">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Recent Analyses
            </h2>
            <Link
              href="/jobs"
              className="text-xs text-accent-strong hover:underline"
            >
              View all
            </Link>
          </div>
          <div className="divide-y divide-border-light">
            {jobs.length === 0 ? (
              <div className="px-4 py-6 text-center text-xs text-text-muted">
                No recent analyses found.
              </div>
            ) : (
              jobs.map((job) => (
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
                      <p className="text-sm text-text-primary">
                        {job.sample_id.slice(0, 12)}
                      </p>
                      <p className="text-xs text-text-muted">
                        {timeAgo(job.created_at)}
                      </p>
                    </div>
                  </div>
                  <span
                    className={`text-xs font-medium uppercase tracking-wider ${STATUS_STYLES[job.status] || "text-text-muted"}`}
                  >
                    {job.status}
                  </span>
                </Link>
              ))
            )}
          </div>
        </div>

        {/* Verdict Distribution */}
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Verdict Distribution
            </h2>
          </div>
          <div className="p-4">
            {verdictData.length === 0 ? (
              <div className="h-44 flex items-center justify-center text-xs text-text-muted">
                No verdict data available.
              </div>
            ) : (
              <>
                {/* Recharts renders an unlabeled SVG; give the chart a text
                    alternative so it isn't opaque to screen readers (the legend
                    below repeats the same figures visually). */}
                <div
                  role="img"
                  aria-label={`Verdict distribution: ${verdictData
                    .map((d) => `${d.name} ${d.value}`)
                    .join(", ")}`}
                >
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie
                      data={verdictData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={70}
                      dataKey="value"
                      strokeWidth={0}
                    >
                      {verdictData.map((_, i) => (
                        <Cell key={i} fill={verdictColors[i]} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "var(--bg-elevated)",
                        border: "1px solid var(--border)",
                        borderRadius: "4px",
                        fontSize: "12px",
                        color: "var(--text-primary)",
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                </div>
                <div className="flex justify-center gap-4 mt-2">
                  {verdictData.map((d, i) => (
                    <div key={d.name} className="flex items-center gap-1.5">
                      <span
                        className="w-2 h-2 rounded-full"
                        style={{ background: verdictColors[i] }}
                      />
                      <span className="text-xs text-text-secondary">
                        {d.name} ({d.value})
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
