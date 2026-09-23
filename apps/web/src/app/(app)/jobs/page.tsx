"use client";

/**
 * Every analysis, in one list.
 *
 * `/reports` used to be this page with `status=completed` already applied and
 * a verdict column instead of a status one — the same rows, the same links,
 * reached two ways. It redirects here now, and the verdict it carried is a
 * column on the rows that have one.
 */

import { getErrorMessage } from "@/lib/errors";
import { Suspense, useCallback, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { FileText, X } from "lucide-react";
import { api } from "@/lib/api";
import {
  analysisRows,
  countByStatus,
  statusFilterFrom,
  STATUS_FILTERS,
  type AnalysisRow,
  type StatusFilter,
} from "@/lib/analyses";
import { countLabel, formatDuration, timeAgo } from "@/lib/report-utils";
import { verdictLabel, verdictTone } from "@/lib/verdict";

const STATUS_BADGE: Record<string, { class: string; dot: string }> = {
  completed: { class: "text-status-green", dot: "bg-status-green" },
  running: { class: "text-status-blue", dot: "bg-status-blue" },
  pending: { class: "text-text-muted", dot: "bg-text-muted" },
  failed: { class: "text-status-red", dot: "bg-status-red" },
  cancelled: { class: "text-text-muted", dot: "bg-text-muted" },
};

function AnalysesList() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const filter: StatusFilter = statusFilterFrom(searchParams.get("status"));

  const [rows, setRows] = useState<AnalysisRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmJob, setConfirmJob] = useState<AnalysisRow | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [refreshError, setRefreshError] = useState<string | null>(null);

  /* Both halves of a row, asked for together. A verdict is worth having and
   * not worth failing the page over, so a reports call that fails leaves the
   * jobs listed without their verdicts rather than leaving nothing listed. */
  const load = useCallback(async () => {
    const [jobs, reports] = await Promise.all([
      api.getJobs(1, 100),
      api.getReports(1, 100).catch(() => null),
    ]);
    return analysisRows(jobs.items, reports?.items ?? []);
  }, []);

  useEffect(() => {
    (async () => {
      try {
        setRows(await load());
      } catch (err) {
        setError(getErrorMessage(err) || "Failed to load analyses.");
      } finally {
        setLoading(false);
      }
    })();
  }, [load]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 4000);
    return () => clearTimeout(t);
  }, [toast]);

  const refresh = async () => {
    try {
      setRows(await load());
      setRefreshError(null);
    } catch (err) {
      // The list stays stale on failure, so say so rather than silently
      // showing old rows.
      setRefreshError(
        `${getErrorMessage(err) || "Failed to refresh the list."} The rows below may be out of date.`,
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
      await refresh();
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

  /* Escape must dismiss the dialog —
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

  /* The filter lives in the URL, which is what lets `/reports` redirect to
   * this page with the status it always meant. */
  const setFilter = (next: StatusFilter) =>
    router.replace(next === "all" ? "/jobs" : `/jobs?status=${next}`);

  const counts = countByStatus(rows);
  const filtered = filter === "all" ? rows : rows.filter((r) => r.status === filter);

  if (loading) {
    return (
      <div className="animate-pulse">
        <div className="h-8 w-48 bg-bg-active rounded mb-4" />
        <div className="flex flex-col md:flex-row gap-6">
          <div className="w-full md:w-48 shrink-0">
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
      <h1 className="sr-only">Analyses</h1>
      {refreshError && (
        <div
          role="alert"
          className="mb-4 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
        >
          {refreshError}
        </div>
      )}
      <div className="flex flex-col md:flex-row gap-6">
        {/* Filter Sidebar */}
        <div className="w-full md:w-48 shrink-0">
          <div className="bg-bg-surface border border-border rounded p-3">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">Filters</h2>
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
              {STATUS_FILTERS.map((f) => {
                const active = filter === f;
                const count = f === "all" ? rows.length : counts[f] || 0;
                return (
                  <button
                    key={f}
                    onClick={() => setFilter(f)}
                    aria-pressed={active}
                    className={`w-full flex items-center justify-between px-2 py-1.5 rounded text-xs ${
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

        {/* The list */}
        <div className="flex-1 min-w-0 bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Analyses &mdash; {countLabel(filtered.length, "result")}
            </h2>
            {/* The count, announced. An explicit role *replaces* an element's
                native one, so putting `status` on the heading above would have
                taken the heading away from the outline this page just gained.
                A node of its own carries the liveness, which is what the
                conversation filter already does. */}
            <span role="status" className="sr-only">
              {countLabel(filtered.length, "result")}
            </span>
            {toast && (
              <span className="text-xs text-status-green bg-status-green/10 border border-status-green/20 rounded px-2 py-0.5">
                {toast}
              </span>
            )}
          </div>
          <div className="divide-y divide-border-light">
            {filtered.length === 0 ? (
              <div className="px-4 py-8 text-center text-xs text-text-muted">
                {filter === "all"
                  ? "Nothing has been analysed yet. Upload a sample to start a run."
                  : `No ${filter} analysis.`}
              </div>
            ) : (
              filtered.map((row) => {
                const badge = STATUS_BADGE[row.status] || STATUS_BADGE.pending;
                const canCancel = row.status === "pending" || row.status === "running";
                const duration = formatDuration(row.durationSeconds);
                return (
                  <div
                    key={row.id}
                    className="flex items-center justify-between px-4 py-3 hover:bg-bg-hover"
                  >
                    {/* The verdict, the score and the status used to be
                        siblings *outside* the link, so dozens of rows for one
                        file were dozens of links all named the same thing.
                        They are inside it now, which is also where a reader
                        following one expects to find them. */}
                    <Link
                      href={`/analysis/${row.id}`}
                      className="flex items-center gap-3 flex-1 min-w-0"
                    >
                      <FileText size={16} aria-hidden="true" className="text-text-secondary shrink-0" />
                      <div className="min-w-0">
                        <p className="text-sm text-text-primary truncate" title={row.sample}>
                          {row.sample}
                        </p>
                        <p className="text-xs text-text-muted">
                          {timeAgo(row.createdAt)}
                          {row.durationSeconds ? ` / ${duration}` : ""}
                        </p>
                      </div>
                      {row.verdict && (
                        <span className={`ml-auto text-xs ${verdictTone(row.verdict).text}`}>
                          {verdictLabel(row.verdict)}
                          {/* A bare `0` beside a confident verdict said
                              nothing about what the number was. */}
                          {row.confidence !== null && (
                            <span className="ml-1.5 font-mono text-text-muted">
                              confidence {row.confidence.toFixed(2)}
                            </span>
                          )}
                        </span>
                      )}
                    </Link>
                    <div className="flex items-center gap-3 ml-3">
                      {canCancel && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setCancelError(null);
                            setConfirmJob(row);
                          }}
                          className="px-3 py-1 text-xs border border-status-red/30 text-status-red rounded hover:bg-status-red/10"
                        >
                          Cancel
                        </button>
                      )}
                      <div className={`flex items-center gap-1.5 ${badge.class}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${badge.dot}`} />
                        <span className="text-xs font-medium uppercase tracking-wider">
                          {row.status}
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
                <X size={16} aria-hidden="true" />
              </button>
            </div>
            <p className="text-sm text-text-secondary mb-4 leading-relaxed">
              Cancelling job {confirmJob.id.slice(0, 8)} stops the analysis where it is and
              marks the job cancelled. It cannot be undone.
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
                className="px-3 py-1 text-xs border border-border text-text-secondary rounded hover:bg-bg-hover disabled:text-text-disabled"
              >
                Keep running
              </button>
              <button
                onClick={handleConfirmCancel}
                disabled={cancelling}
                className="px-3 py-1 text-xs bg-status-red text-bg-deep rounded hover:bg-status-red/90 disabled:opacity-50"
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

/* `useSearchParams` reads a value that only exists once the request is known,
 * so the list is rendered under a boundary rather than prerendered without it. */
export default function JobsPage() {
  return (
    <Suspense fallback={<p className="text-sm text-text-secondary">Loading analyses…</p>}>
      <AnalysesList />
    </Suspense>
  );
}
