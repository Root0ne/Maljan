"use client";

import Link from "next/link";
import { usePathname, useParams } from "next/navigation";
import { useEffect, useState, createContext, useContext } from "react";
import { api } from "@/lib/api";
import type { ReportDetailDTO, JobDTO } from "@/lib/api";

/* ── Report Context (shared with child tabs) ─────────── */
interface ReportCtx {
  report: ReportDetailDTO | null;
  job: JobDTO | null;
  loading: boolean;
}

const ReportContext = createContext<ReportCtx>({ report: null, job: null, loading: true });
export function useReport() {
  return useContext(ReportContext);
}

/* ── Verdict badge config ────────────────────────────── */
const VERDICT_CONFIG: Record<
  string,
  { bg: string; border: string; text: string; label: string; icon: string }
> = {
  malicious: {
    bg: "bg-status-red/10",
    border: "border-status-red/30",
    text: "text-status-red",
    label: "Malicious",
    icon: "!",
  },
  suspicious: {
    bg: "bg-status-orange/10",
    border: "border-status-orange/30",
    text: "text-status-orange",
    label: "Suspicious",
    icon: "?",
  },
  benign: {
    bg: "bg-status-green/10",
    border: "border-status-green/30",
    text: "text-status-green",
    label: "Benign",
    icon: "\u2713",
  },
  unknown: {
    bg: "bg-text-muted/10",
    border: "border-text-muted/30",
    text: "text-text-muted",
    label: "Unknown",
    icon: "-",
  },
};

const TABS = [
  { key: "", label: "SUMMARY" },
  { key: "/agents", label: "AGENTS" },
  { key: "/rules", label: "RULES" },
  { key: "/ttps", label: "TTPS" },
  { key: "/timeline", label: "TIMELINE" },
  { key: "/stix", label: "STIX" },
];

/* ── Mock fallback data ─────────────────────────────── */
const MOCK_REPORT: Partial<ReportDetailDTO> = {
  verdict: "malicious",
  overall_confidence: 87,
  malware_category: "Trojan.Emotet",
  created_at: new Date().toISOString(),
};

const MOCK_JOB: Partial<JobDTO> = {
  id: "mock-job",
  sample_id: "mock-sample",
  status: "completed",
  duration_seconds: 252,
  created_at: new Date().toISOString(),
};

function formatDuration(seconds: number | null | undefined): string {
  if (!seconds) return "N/A";
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${String(s).padStart(2, "0")}s`;
}

export default function AnalysisLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const params = useParams();
  const pathname = usePathname();
  const id = params.id as string;
  const basePath = `/analysis/${id}`;

  const [report, setReport] = useState<ReportDetailDTO | null>(null);
  const [job, setJob] = useState<JobDTO | null>(null);
  const [loading, setLoading] = useState(true);
  const [apiAvailable, setApiAvailable] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        // First fetch the job
        const j = await api.getJob(id);
        setJob(j);

        // Then try to fetch the report for this job
        // The report endpoint uses report ID, but we may need to get it from the job
        // For now we try report by job ID
        try {
          const r = await api.getReport(id);
          setReport(r);
        } catch {
          /* report may not exist yet if job is still running */
        }
        setApiAvailable(true);
      } catch {
        /* use mock fallback */
      } finally {
        setLoading(false);
      }
    })();
  }, [id]);

  /* Derive header data from real report or mock */
  const verdict = report?.verdict || (MOCK_REPORT.verdict as string);
  const confidence = report?.overall_confidence ?? MOCK_REPORT.overall_confidence ?? 0;
  const category = report?.malware_category || MOCK_REPORT.malware_category || "";
  const sampleId = job?.sample_id || MOCK_JOB.sample_id || "";
  const duration = formatDuration(job?.duration_seconds ?? MOCK_JOB.duration_seconds);
  const analyzedAt = report?.created_at
    ? new Date(report.created_at).toLocaleString()
    : new Date().toLocaleString();

  const v = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.unknown;

  return (
    <ReportContext.Provider value={{ report, job, loading }}>
      <div>
        {!apiAvailable && !loading && (
          <div className="mb-4 p-2.5 text-xs text-status-orange bg-status-orange/10 border border-status-orange/20 rounded">
            API not available. Showing demo data.
          </div>
        )}

        {/* Header */}
        <div className="bg-bg-surface border border-border rounded p-4 mb-4">
          <div className="flex items-start gap-5">
            {/* Verdict Badge */}
            <div
              className={`flex items-center justify-center w-16 h-16 rounded-full border-2 ${v.bg} ${v.border} shrink-0`}
            >
              <span className={`text-2xl font-bold ${v.text}`}>{v.icon}</span>
            </div>

            {/* Info */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-1">
                <h1 className={`text-lg font-semibold ${v.text}`}>
                  {v.label}
                </h1>
                <span className="text-xs text-text-secondary bg-bg-active px-2 py-0.5 rounded">
                  Score: {confidence}/100
                </span>
                {category && (
                  <span className="text-xs text-text-secondary bg-bg-active px-2 py-0.5 rounded">
                    {category}
                  </span>
                )}
                {job && (
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    job.status === "completed" ? "text-status-green bg-status-green/10" :
                    job.status === "running" ? "text-status-blue bg-status-blue/10" :
                    job.status === "failed" ? "text-status-red bg-status-red/10" :
                    "text-text-muted bg-bg-active"
                  }`}>
                    {job.status.toUpperCase()}
                  </span>
                )}
              </div>

              <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-text-secondary">
                <div>
                  <span className="text-text-muted">Sample: </span>
                  <code className="font-mono">{sampleId.slice(0, 12)}</code>
                </div>
                <div>
                  <span className="text-text-muted">Duration: </span>
                  {duration}
                </div>
                <div>
                  <span className="text-text-muted">Analyzed: </span>
                  {analyzedAt}
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Tab Bar */}
        <div className="flex border-b border-border mb-4">
          {TABS.map((tab) => {
            const href = `${basePath}${tab.key}`;
            const active =
              tab.key === ""
                ? pathname === basePath
                : pathname.startsWith(href);
            return (
              <Link
                key={tab.key}
                href={href}
                className={`px-4 py-2.5 text-xs font-medium uppercase tracking-wider border-b-2 transition-colors ${
                  active
                    ? "border-accent text-accent"
                    : "border-transparent text-text-secondary hover:text-text-primary"
                }`}
              >
                {tab.label}
              </Link>
            );
          })}
        </div>

        {/* Tab Content */}
        {children}
      </div>
    </ReportContext.Provider>
  );
}
