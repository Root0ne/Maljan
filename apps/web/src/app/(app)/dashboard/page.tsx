"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { DashboardStatsDTO, JobDTO } from "@/lib/api";
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

/* ── Mock data for demo (until backend is connected) ── */
const MOCK_STATS: DisplayStats = {
  total_jobs: 142,
  total_samples: 89,
  completed: 128,
  running: 3,
  failed: 11,
  malicious_count: 67,
  suspicious_count: 34,
  benign_count: 27,
  avg_duration_seconds: 245,
};

const MOCK_JOBS: JobDTO[] = [
  { id: "11111111-1111-1111-1111-111111111111", sample_id: "s-11111111-1111-1111-1111-111111111111", status: "completed", config: null, created_at: new Date(Date.now() - 3600000).toISOString(), started_at: null, completed_at: new Date(Date.now() - 3200000).toISOString(), duration_seconds: 400, error_message: null },
  { id: "22222222-2222-2222-2222-222222222222", sample_id: "s-22222222-2222-2222-2222-222222222222", status: "running", config: null, created_at: new Date(Date.now() - 1800000).toISOString(), started_at: null, completed_at: null, duration_seconds: null, error_message: null },
  { id: "33333333-3333-3333-3333-333333333333", sample_id: "s-33333333-3333-3333-3333-333333333333", status: "completed", config: null, created_at: new Date(Date.now() - 7200000).toISOString(), started_at: null, completed_at: new Date(Date.now() - 6800000).toISOString(), duration_seconds: 400, error_message: null },
  { id: "44444444-4444-4444-4444-444444444444", sample_id: "s-44444444-4444-4444-4444-444444444444", status: "failed", config: null, created_at: new Date(Date.now() - 10800000).toISOString(), started_at: null, completed_at: null, duration_seconds: null, error_message: "Sandbox timeout" },
  { id: "55555555-5555-5555-5555-555555555555", sample_id: "s-55555555-5555-5555-5555-555555555555", status: "completed", config: null, created_at: new Date(Date.now() - 14400000).toISOString(), started_at: null, completed_at: new Date(Date.now() - 14000000).toISOString(), duration_seconds: 400, error_message: null },
];

const MOCK_NAMES: Record<string, string> = {
  "s-11111111-1111-1111-1111-111111111111": "emotet_dropper.exe",
  "s-22222222-2222-2222-2222-222222222222": "lockbit3_ransom.dll",
  "s-33333333-3333-3333-3333-333333333333": "cobalt_beacon.bin",
  "s-44444444-4444-4444-4444-444444444444": "legit_installer.msi",
  "s-55555555-5555-5555-5555-555555555555": "qakbot_loader.js",
};

function mapApiStats(s: DashboardStatsDTO): DisplayStats {
  const byStatus = s.jobs_by_status || {};
  const byVerdict = s.verdict_distribution || {};
  return {
    total_jobs: s.total_jobs,
    total_samples: s.total_samples,
    completed: byStatus["completed"] || 0,
    running: byStatus["running"] || 0,
    failed: byStatus["failed"] || 0,
    malicious_count: byVerdict["malicious"] || 0,
    suspicious_count: byVerdict["suspicious"] || 0,
    benign_count: byVerdict["benign"] || 0,
    avg_duration_seconds: s.avg_duration_seconds || 0,
  };
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DisplayStats>(MOCK_STATS);
  const [jobs, setJobs] = useState<JobDTO[]>(MOCK_JOBS);
  const [apiAvailable, setApiAvailable] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const s = await api.getDashboardStats();
        setStats(mapApiStats(s));
        const j = await api.getJobs(1, 10);
        setJobs(j.items.slice(0, 10));
        setApiAvailable(true);
      } catch {
        /* use mock data */
      }
    })();
  }, []);

  const verdictData = [
    { name: "Malicious", value: stats.malicious_count },
    { name: "Suspicious", value: stats.suspicious_count },
    { name: "Benign", value: stats.benign_count },
  ].filter((d) => d.value > 0);

  const verdictColors = [
    VERDICT_COLORS.malicious,
    VERDICT_COLORS.suspicious,
    VERDICT_COLORS.benign,
  ];

  return (
    <div>
      {!apiAvailable && (
        <div className="mb-4 p-2.5 text-xs text-status-orange bg-status-orange/10 border border-status-orange/20 rounded">
          API not available. Showing demo data.
        </div>
      )}

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard label="Total Analyses" value={stats.total_jobs} />
        <StatCard
          label="Completed"
          value={stats.completed}
          sub={`${stats.running} running`}
        />
        <StatCard
          label="Failed"
          value={stats.failed}
          sub={`${((stats.failed / Math.max(stats.total_jobs, 1)) * 100).toFixed(1)}% failure rate`}
        />
        <StatCard
          label="Avg Duration"
          value={formatDuration(stats.avg_duration_seconds)}
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
              className="text-xs text-accent hover:underline"
            >
              View all
            </Link>
          </div>
          <div className="divide-y divide-border-light">
            {jobs.map((job) => (
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
                      {MOCK_NAMES[job.sample_id] || job.sample_id.slice(0, 12)}
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
            ))}
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
          </div>
        </div>
      </div>
    </div>
  );
}
