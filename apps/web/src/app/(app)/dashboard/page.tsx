"use client";

import { getErrorMessage } from "@/lib/errors";
import { useEffect, useState } from "react";
import Link from "next/link";
import { FileText } from "lucide-react";
import { api } from "@/lib/api";
import type { DashboardStatsDTO, JobDTO, SystemStatusDTO } from "@/lib/api";
import { sampleLabel } from "@/lib/analyses";
import { formatDuration, timeAgo } from "@/lib/report-utils";
import { verdictBucket } from "@/lib/verdict";
import { enrichmentWorkerNotice } from "./enrichmentNotice";
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

/* Five, because this is a way in rather than a list. The full list is one
 * click away and pages properly; restating ten of its rows here made the
 * dashboard a second, worse copy of it. */
const LATEST_RUNS = 5;

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

function mapApiStats(s: DashboardStatsDTO): DisplayStats {
  const byStatus = s.jobs_by_status || {};
  const byVerdict = s.verdict_distribution || {};

  // The API returns the MalwareReport verdict casing
  // ("Malware", "Suspicious", "Benign") plus legacy "malicious" from older
  // rows. Funnel every key through the shared `verdictBucket` instead of a
  // hand-rolled lowercase map so the dashboard agrees with every other
  // surface — and so a new backend spelling only has to be taught once.
  const verdictLookup: Record<string, number> = {};
  for (const [key, value] of Object.entries(byVerdict)) {
    const bucket = verdictBucket(key);
    verdictLookup[bucket] = (verdictLookup[bucket] || 0) + (value || 0);
  }

  return {
    total_jobs: s.total_jobs,
    total_samples: s.total_samples,
    completed: byStatus["completed"] || 0,
    running: byStatus["running"] || 0,
    failed: byStatus["failed"] || 0,
    malicious_count: verdictLookup["malicious"] || 0,
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
          api.getJobs(1, LATEST_RUNS),
          // System status is best-effort: failure here must not block the
          // rest of the dashboard from rendering.
          api.getSystemStatus().catch(() => null),
        ]);
        setStats(mapApiStats(s));
        setJobs(j.items.slice(0, LATEST_RUNS));
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
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <StatCardSkeleton />
          <StatCardSkeleton />
          <StatCardSkeleton />
          <StatCardSkeleton />
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 bg-bg-surface border border-border rounded animate-pulse">
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

  const enrichment = enrichmentWorkerNotice(systemStatus?.enrichment_worker);

  return (
    <div>
      {/* The page's own name. Visually hidden because the rail already says
          where the reader is; an outline that starts at h2 does not. */}
      <h1 className="sr-only">Dashboard</h1>

      {/* Mock-mode banner: operators
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

      {/* Enrichment queued for a worker that is not there. Said in words
          rather than left to a colour, and only in the one state an operator
          can do something about; the rest of what the field can say is the
          system working. */}
      {enrichment && (
        <div
          role="status"
          className="mb-4 flex flex-wrap items-start gap-x-3 gap-y-1 rounded border border-status-orange/40 bg-status-orange/10 p-3 text-sm"
        >
          <span className="font-semibold text-status-orange">{enrichment.label}</span>
          <span className="text-text-secondary">{enrichment.detail}</span>
          <span className="text-text-muted">
            Setting: <code>{enrichment.setting}</code>
          </span>
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Recent Analyses */}
        <div className="lg:col-span-2 bg-bg-surface border border-border rounded">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Latest runs
            </h2>
            <Link
              href="/jobs"
              className="text-xs text-accent-strong hover:underline"
            >
              Every analysis
            </Link>
          </div>
          <div className="divide-y divide-border-light">
            {jobs.length === 0 ? (
              <div className="px-4 py-6 text-center text-xs text-text-muted">
                Nothing has been analysed yet.
              </div>
            ) : (
              jobs.map((job) => (
                <Link
                  key={job.id}
                  href={`/analysis/${job.id}`}
                  className="flex items-center justify-between px-4 py-3 hover:bg-bg-hover"
                >
                  <div className="flex items-center gap-3">
                    <FileText size={16} aria-hidden="true" className="text-text-secondary" />
                    <div>
                      <p className="text-sm text-text-primary">
                        {sampleLabel(job)}
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
                  {/* The labelled wrapper above is the chart's one node in the
                      accessibility tree; Recharts' own surface and pie would
                      otherwise be two more tab stops with no name. */}
                  <PieChart accessibilityLayer={false} tabIndex={-1} role="presentation">
                    <Pie
                      data={verdictData}
                      cx="50%"
                      cy="50%"
                      innerRadius={50}
                      outerRadius={70}
                      dataKey="value"
                      strokeWidth={0}
                      tabIndex={-1}
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
