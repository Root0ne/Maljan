"use client";

import { getErrorMessage } from "@/lib/errors";
import { useState, useEffect } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { JobDTO } from "@/lib/api";
import { formatDuration, timeAgo } from "@/lib/report-utils";

interface DisplayJob {
  id: string;
  sample_id: string;
  // audit 2026-07-26 (T4): carry the readable sample identity so rows are
  // distinguishable instead of all showing the same sample_id UUID prefix.
  sample_filename: string | null;
  sample_sha256: string | null;
  status: string;
  created_at: string;
  duration: string | null;
}

function mapJob(j: JobDTO): DisplayJob {
  return {
    id: j.id,
    sample_id: j.sample_id,
    sample_filename: j.sample_filename ?? null,
    sample_sha256: j.sample_sha256 ?? null,
    status: j.status,
    created_at: j.created_at,
    duration: j.duration_seconds ? formatDuration(j.duration_seconds) : null,
  };
}

/* Same precedence as the analysis header (analysis/[id]/layout.tsx). */
function sampleLabel(job: DisplayJob): string {
  return (
    job.sample_filename ||
    (job.sample_sha256 ? `${job.sample_sha256.slice(0, 16)}…` : "") ||
    job.sample_id.slice(0, 12)
  );
}

const STATUS_BADGE: Record<string, { class: string; dot: string }> = {
  completed: { class: "text-status-green", dot: "bg-status-green" },
  running: { class: "text-status-blue", dot: "bg-status-blue" },
  pending: { class: "text-text-muted", dot: "bg-text-muted" },
  failed: { class: "text-status-red", dot: "bg-status-red" },
  cancelled: { class: "text-text-muted", dot: "bg-text-muted" },
};

const FILTERS = ["all", "completed", "running", "pending", "failed", "cancelled"];

function countByStatus(jobs: DisplayJob[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const j of jobs) {
    counts[j.status] = (counts[j.status] || 0) + 1;
  }
  return counts;
}

export default function JobsPage() {
  const [filter, setFilter] = useState("all");
  const [jobs, setJobs] = useState<DisplayJob[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmJob, setConfirmJob] = useState<DisplayJob | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [refreshError, setRefreshError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const res = await api.getJobs(1, 100);
        setJobs(res.items.map(mapJob));
      } catch (err) {
        setError(getErrorMessage(err) || "Failed to load jobs.");
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  const refreshJobs = async () => {
    try {
      const res = await api.getJobs(1, 100);
      setJobs(res.items.map(mapJob));
      setRefreshError(null);
    } catch (err) {
      // audit 2026-07-26 (§4 "sessizce yutulan hatalar"): the list stays
      // stale on failure, so say so rather than silently showing old rows.
      setRefreshError(
        `${getErrorMessage(err) || "Failed to refresh jobs."} The list below may be out of date.`,
      );
    }
  };

  const handleConfirmCancel = async () => {
    if (!confirmJob) return;
    setCancelling(true);
    setCancelError(null);
    const idPrefix = confirmJob.id.slice(0, 8);
    try {
      await api.cancelJob(confirmJob.id);
      setConfirmJob(null);
      await refreshJobs();
      setToast(`Job ${idPrefix} cancelled.`);
    } catch (err) {
      setCancelError(getErrorMessage(err) || "Failed to cancel job.");
    } finally {
      setCancelling(false);
    }
  };

  const closeModal = () => {
    if (cancelling) return;
    setConfirmJob(null);
    setCancelError(null);
  };

  /* audit 2026-07-26 (§4 accessibility): Escape must dismiss the dialog —
   * same keydown pattern the search palette uses. */
  useEffect(() => {
    if (!confirmJob) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.preventDefault();
      if (cancelling) return;
      setConfirmJob(null);
      setCancelError(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [confirmJob, cancelling]);

  const counts = countByStatus(jobs);
  const filtered = filter === "all" ? jobs : jobs.filter((j) => j.status === filter);

  if (loading) {
    return (
      <div className="animate-pulse">
        <div className="h-8 w-48 bg-bg-active rounded mb-4" />
        <div className="flex gap-6">
          <div className="w-48 shrink-0">
            <div className="h-64 bg-bg-surface border border-border rounded" />
          </div>
          <div className="flex-1 bg-bg-surface border border-border rounded">
            <div className="h-10 border-b border-border" />
            <div className="p-4 space-y-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="h-10 bg-bg-active rounded" />
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div role="alert" className="p-4 text-sm text-status-red bg-status-red/10 border border-status-red/20 rounded">
        {error}
      </div>
    );
  }

  return (
    <div>
      {refreshError && (
        <div
          role="alert"
          className="mb-4 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
        >
          {refreshError}
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
          <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Analysis Jobs &mdash; {filtered.length} results
            </h2>
            {toast && (
              <span className="text-xs text-status-green bg-status-green/10 border border-status-green/20 rounded px-2 py-0.5">
                {toast}
              </span>
            )}
          </div>
          <div className="divide-y divide-border-light">
            {filtered.length === 0 ? (
              <div className="px-4 py-8 text-center text-xs text-text-muted">
                No jobs found.
              </div>
            ) : (
              filtered.map((job) => {
                const badge = STATUS_BADGE[job.status] || STATUS_BADGE.pending;
                const canCancel = job.status === "pending" || job.status === "running";
                return (
                  <div
                    key={job.id}
                    className="flex items-center justify-between px-4 py-3 hover:bg-bg-hover transition-colors"
                  >
                    <Link
                      href={`/analysis/${job.id}`}
                      className="flex items-center gap-3 flex-1 min-w-0"
                    >
                      <svg
                        width="14" height="14" viewBox="0 0 24 24" fill="none"
                        stroke="var(--text-secondary)" strokeWidth="1.5"
                      >
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
                        <path d="M14 2v6h6" />
                      </svg>
                      <div className="min-w-0">
                        <p className="text-sm text-text-primary truncate" title={sampleLabel(job)}>{sampleLabel(job)}</p>
                        <p className="text-xs text-text-muted">{timeAgo(job.created_at)}{job.duration ? ` / ${job.duration}` : ""}</p>
                      </div>
                    </Link>
                    <div className="flex items-center gap-3 ml-3">
                      {canCancel && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setCancelError(null);
                            setConfirmJob(job);
                          }}
                          className="px-3 py-1 text-xs border border-status-red/30 text-status-red rounded hover:bg-status-red/10 transition-colors"
                        >
                          Cancel
                        </button>
                      )}
                      <div className={`flex items-center gap-1.5 ${badge.class}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${badge.dot}`} />
                        <span className="text-xs font-medium uppercase tracking-wider">
                          {job.status}
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Cancel Confirmation Modal */}
      {confirmJob && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={closeModal}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="cancel-job-title"
            className="bg-bg-surface border border-border rounded w-full max-w-md p-5 shadow-lg"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 id="cancel-job-title" className="text-sm font-semibold text-text-primary">Cancel Job</h3>
              <button
                type="button"
                aria-label="Close"
                onClick={closeModal}
                disabled={cancelling}
                className="text-text-muted hover:text-text-primary disabled:text-text-disabled"
              >
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>
            <p className="text-sm text-text-secondary mb-4 leading-relaxed">
              Cancel job {confirmJob.id.slice(0, 8)}? This will stop the in-flight analysis and mark the job as cancelled. Cannot be undone.
            </p>
            {cancelError && (
              <div role="alert" className="mb-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5">
                {cancelError}
              </div>
            )}
            <div className="flex justify-end gap-2">
              <button
                onClick={closeModal}
                disabled={cancelling}
                className="px-3 py-1 text-xs border border-border text-text-secondary rounded hover:bg-bg-hover transition-colors disabled:text-text-disabled"
              >
                Keep running
              </button>
              <button
                onClick={handleConfirmCancel}
                disabled={cancelling}
                className="px-3 py-1 text-xs bg-status-red text-bg-deep rounded hover:bg-status-red/90 transition-colors disabled:opacity-50"
              >
                {cancelling ? "Cancelling..." : "Cancel job"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
