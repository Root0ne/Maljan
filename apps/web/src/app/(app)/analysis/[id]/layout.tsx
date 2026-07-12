"use client";

import Link from "next/link";
import { usePathname, useParams } from "next/navigation";
import { useEffect, useRef, useState, createContext, useContext } from "react";
import { api } from "@/lib/api";
import type { ReportDetailDTO, JobDTO } from "@/lib/api";
import { useWebSocket } from "@/lib/useWebSocket";

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
  malware: {
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

interface TabDef {
  key: string;
  label: string;
  group: "overview" | "analysis" | "intel" | "advanced";
}

const TABS: TabDef[] = [
  { key: "", label: "SUMMARY", group: "overview" },
  { key: "/identity", label: "IDENTITY", group: "overview" },
  { key: "/static", label: "STATIC", group: "analysis" },
  { key: "/dynamic", label: "DYNAMIC", group: "analysis" },
  { key: "/network", label: "NETWORK", group: "analysis" },
  { key: "/persistence", label: "PERSISTENCE", group: "analysis" },
  { key: "/capabilities", label: "ATT&CK", group: "intel" },
  { key: "/attribution", label: "ATTRIBUTION", group: "intel" },
  { key: "/signatures", label: "SIGNATURES", group: "intel" },
  { key: "/defense", label: "DEFENSE", group: "intel" },
  { key: "/agents", label: "AGENTS", group: "advanced" },
  { key: "/pipeline", label: "PIPELINE", group: "advanced" },
  { key: "/rules", label: "RULES", group: "advanced" },
  { key: "/timeline", label: "TIMELINE", group: "advanced" },
  { key: "/stix", label: "STIX", group: "advanced" },
  { key: "/live", label: "LIVE", group: "advanced" },
];

const TAB_GROUP_ORDER: TabDef["group"][] = ["overview", "analysis", "intel", "advanced"];

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
  const [enrichmentToast, setEnrichmentToast] = useState<string | null>(null);
  const refetchRef = useRef<(() => Promise<void>) | null>(null);

  useEffect(() => {
    let cancelled = false;
    const TERMINAL = new Set(["completed", "failed"]);
    const POLL_INTERVAL = 3000;

    async function refetchReport() {
      if (cancelled) return;
      try {
        const r = await api.getReportByJobId(id);
        if (!cancelled) setReport(r);
      } catch {
        /* report still propagating; ignore */
      }
    }
    refetchRef.current = refetchReport;

    async function fetchAll() {
      try {
        const j = await api.getJob(id);
        if (cancelled) return;
        setJob(j);
        setApiAvailable(true);

        if (TERMINAL.has(j.status)) {
          await refetchReport();
          if (!cancelled) setLoading(false);
          return; // stop polling
        }

        // Job still running — schedule next poll
        if (!cancelled) setLoading(false);
        setTimeout(() => { if (!cancelled) fetchAll(); }, POLL_INTERVAL);
      } catch {
        /* API not reachable */
        if (!cancelled) setLoading(false);
      }
    }

    fetchAll();
    return () => { cancelled = true; };
  }, [id]);

  /* WS listener — react to enrichment_complete (and late completed) without
   * waiting for polling to come back. */
  const { events } = useWebSocket(id);
  const lastWsCursor = useRef(0);
  useEffect(() => {
    if (events.length <= lastWsCursor.current) return;
    for (let i = lastWsCursor.current; i < events.length; i++) {
      const e = events[i];
      if (e.type === "enrichment_complete" || e.type === "completed") {
        refetchRef.current?.();
        if (e.type === "enrichment_complete") {
          setEnrichmentToast("Threat intel enrichment finished. Report refreshed.");
          setTimeout(() => setEnrichmentToast(null), 5000);
        }
      }
    }
    lastWsCursor.current = events.length;
  }, [events]);

  /* Derive header data strictly from real API data — no mock fallback */
  const verdict = report?.verdict?.toLowerCase() ?? "unknown";
  const confidence = Math.round((report?.overall_confidence ?? 0) * 100);
  const category = report?.malware_category ?? "";
  // BUG-02: prefer a readable sample identity (filename, then hash prefix) over
  // the opaque sample_id UUID — available from the job even during the live run,
  // before the rich report's identity payload lands.
  const sampleId = job?.sample_id ?? "";
  const jobSampleLabel =
    job?.sample_filename ||
    (job?.sample_sha256 ? `${job.sample_sha256.slice(0, 16)}…` : "");
  const duration = formatDuration(job?.duration_seconds);
  const analyzedAt = report?.created_at
    ? new Date(report.created_at).toLocaleString()
    : job?.created_at ? new Date(job.created_at).toLocaleString() : "";

  const v = VERDICT_CONFIG[verdict] || VERDICT_CONFIG.unknown;

  /* The H1 should identify the sample, not restate the verdict (the verdict
   * badge already shows it). Prefer the original filename from the rich
   * MalwareReport identity payload; fall back to a hash prefix if neither
   * the report nor the legacy fields have it. */
  const identity = report?.malware_report?.identity;
  const fileName = identity?.file_name?.trim();
  const sha256 = identity?.hashes?.sha256;
  const headerTitle =
    fileName || (sha256 ? `${sha256.slice(0, 16)}…` : "") || jobSampleLabel || "Pending analysis";
  const family = report?.malware_report?.attribution?.family;
  const headerSubtitle = family || category || "";

  return (
    <ReportContext.Provider value={{ report, job, loading }}>
      <div>
        {!apiAvailable && !loading && (
          <div className="mb-4 p-2.5 text-xs text-status-orange bg-status-orange/10 border border-status-orange/20 rounded">
            Could not connect to the API. Please ensure the backend is running.
          </div>
        )}

        {enrichmentToast && (
          <div className="mb-4 p-2.5 text-xs text-status-blue bg-status-blue/10 border border-status-blue/20 rounded">
            {enrichmentToast}
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
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 mb-1">
                <h1 className="text-lg font-semibold text-text-primary truncate max-w-full" title={headerTitle}>
                  {headerTitle}
                </h1>
                <span className={`text-xs px-2 py-0.5 rounded ${v.bg} ${v.text}`}>
                  {v.label}
                </span>
                <span className="text-xs text-text-secondary bg-bg-active px-2 py-0.5 rounded">
                  Confidence: {confidence}/100
                </span>
                {headerSubtitle && (
                  <span className="text-xs text-text-secondary bg-bg-active px-2 py-0.5 rounded">
                    {headerSubtitle}
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
                  <code className="font-mono">
                    {fileName || jobSampleLabel || sampleId.slice(0, 12)}
                  </code>
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

        {/* Tab Bar — grouped by section with thin separators */}
        <div className="flex flex-wrap items-end border-b border-border mb-4">
          {TAB_GROUP_ORDER.map((group, gi) => {
            const groupTabs = TABS.filter((t) => t.group === group);
            return (
              <div key={group} className="flex items-end">
                {gi > 0 && (
                  <span
                    aria-hidden="true"
                    className="h-5 w-px bg-border mx-1.5 mb-2 self-center"
                  />
                )}
                {groupTabs.map((tab) => {
                  const href = `${basePath}${tab.key}`;
                  const active =
                    tab.key === ""
                      ? pathname === basePath
                      : pathname.startsWith(href);
                  return (
                    <Link
                      key={tab.key}
                      href={href}
                      className={`px-3 py-2.5 text-xs font-medium uppercase tracking-wider border-b-2 transition-colors ${
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
            );
          })}
        </div>

        {/* Tab Content */}
        {children}
      </div>
    </ReportContext.Provider>
  );
}
