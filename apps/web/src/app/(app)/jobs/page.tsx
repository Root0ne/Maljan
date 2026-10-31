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
import { Suspense, useCallback, useEffect, useId, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { FileText, MoreHorizontal, X } from "lucide-react";
import { api } from "@/lib/api";
import { fetchAllPages } from "@/lib/pages";
import { buttonClass } from "@/components/ui/Button";
import ShowMoreRows from "@/components/ui/ShowMoreRows";
import { ROWS_PER_STEP, visibleRows } from "@/lib/pagedRows";
import {
  analysisRows,
  countByStatus,
  searchRows,
  statusFilterFrom,
  STATUS_FILTERS,
  type AnalysisRow,
  type StatusFilter,
} from "@/lib/analyses";
import { countLabel, formatDuration, timeAgo } from "@/lib/report-utils";
import { statusTone } from "@/lib/status";
import { verdictLabel, verdictTone } from "@/lib/verdict";
import CopyButton from "@/components/ui/CopyButton";

const COPY_CLASS =
  "inline-flex min-h-6 items-center px-2 py-0.5 text-[11px] font-mono border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted";

/**
 * A row's one control besides its link: a button that opens what else can
 * be done with the run. The two values an operator pastes elsewhere (into a
 * lookup, into a log search), one press each with a name that says which
 * row's, and Cancel while the run is still going. A disclosure rather than
 * a menu, so each copy keeps its own announcement; Escape or a click outside
 * closes it and gives the focus back.
 */
function RowActions({ row, onCancel }: { row: AnalysisRow; onCancel: () => void }) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const panelId = useId();
  const canCancel = row.status === "pending" || row.status === "running";
  const when = timeAgo(row.createdAt);

  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      setOpen(false);
      button.current?.focus();
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div ref={root} className="relative shrink-0">
      <button
        ref={button}
        type="button"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        aria-label={`Actions for ${row.sample}, ${when}`}
        onClick={() => setOpen((v) => !v)}
        className={buttonClass("ghost", "sm")}
      >
        <MoreHorizontal aria-hidden="true" className="h-4 w-4" />
      </button>
      {open && (
        <div
          id={panelId}
          role="group"
          aria-label={`Actions for ${row.sample}`}
          className="absolute right-0 z-20 mt-1 flex w-56 max-w-[calc(100vw-2rem)] flex-col items-stretch gap-1.5 rounded-md border border-border bg-bg-surface p-2 shadow-lg"
        >
          {row.sha256 && (
            <CopyButton value={row.sha256} what={`SHA-256 of ${row.sample}, ${when}`} label="SHA-256" className={COPY_CLASS} />
          )}
          <CopyButton value={row.id} what={`job id of ${row.sample}, ${when}`} label="job id" className={COPY_CLASS} />
          {canCancel && (
            <button
              type="button"
              onClick={() => {
                setOpen(false);
                onCancel();
              }}
              className="inline-flex min-h-6 items-center rounded border border-status-red/30 px-2 py-0.5 text-xs text-status-red hover:bg-status-red/10"
            >
              Cancel analysis
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function AnalysesList() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const filter: StatusFilter = statusFilterFrom(searchParams.get("status"));

  const [rows, setRows] = useState<AnalysisRow[]>([]);
  /* Every run is read; a long history is drawn a step at a time (`lib/pagedRows`). */
  const [shown, setShown] = useState(ROWS_PER_STEP);
  const [query, setQuery] = useState("");
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
    // Every page of both, not the newest hundred: a list that stops at page
    // one reads as the whole history (`fetchAllPages`).
    const [jobs, reports] = await Promise.all([
      fetchAllPages((page, size) => api.getJobs(page, size)),
      fetchAllPages((page, size) => api.getReports(page, size)).catch(() => null),
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
      setToast(`Analysis ${idPrefix} cancelled.`);
    } catch (err) {
      setCancelError(getErrorMessage(err) || "Failed to cancel the analysis.");
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
  const filtered = searchRows(filter === "all" ? rows : rows.filter((r) => r.status === filter), query);

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
      <section aria-label="Find an analysis" className="mb-4 flex flex-wrap items-end gap-3">
        <label className="flex min-w-0 flex-1 basis-64 flex-col gap-1 text-xs text-text-secondary">
          Search analyses
          <input
            type="search"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setShown(ROWS_PER_STEP);
            }}
            placeholder="File name, SHA-256, job id or verdict"
            className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 text-sm text-text-primary"
          />
        </label>
        <div role="group" aria-label="Status" className="flex flex-wrap items-center gap-1">
          {STATUS_FILTERS.map((f) => {
            const active = filter === f;
            const count = f === "all" ? rows.length : counts[f] || 0;
            return (
              <button
                key={f}
                type="button"
                onClick={() => setFilter(f)}
                aria-pressed={active}
                className={`inline-flex min-h-7 items-center gap-1.5 rounded border px-2 text-xs ${
                  active
                    ? "border-accent bg-bg-active text-text-primary"
                    : "border-border text-text-secondary hover:border-text-muted hover:text-text-primary"
                }`}
              >
                {f !== "all" && <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${statusTone(f).dot}`} />}
                <span className="capitalize">{f}</span>
                <span className="text-text-muted">{count}</span>
              </button>
            );
          })}
          {(filter !== "all" || query.trim() !== "") && (
            <button
              type="button"
              onClick={() => {
                setQuery("");
                setFilter("all");
              }}
              className="px-1 text-xs text-accent-strong hover:underline"
            >
              Clear
            </button>
          )}
        </div>
      </section>

      <div className="min-w-0 rounded-md border border-border bg-bg-surface">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-text-primary">
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
              {query.trim()
                ? `Not found: no analysis matches "${query.trim()}".`
                : filter === "all"
                  ? "Nothing has been analysed yet. Upload a sample to start a run."
                  : `No ${filter} analysis.`}
            </div>
          ) : (
            visibleRows(filtered, shown).visible.map((row) => {
              const badge = statusTone(row.status);
              const duration = formatDuration(row.durationSeconds);
              return (
                <div key={row.id} className="flex items-center gap-2 px-4 py-3 hover:bg-bg-hover">
                  {/* The verdict, the confidence and the status sit inside
                      the link, so dozens of rows for one file are not dozens
                      of links all named the same thing; the row's one other
                      control is its actions button beside it. */}
                  <Link href={`/analysis/${row.id}`} className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1">
                    <span className="flex min-w-0 flex-1 basis-48 items-center gap-3">
                      <FileText size={16} aria-hidden="true" className="text-text-secondary shrink-0" />
                      <span className="min-w-0">
                        <span className="block text-sm text-text-primary truncate" title={row.sample}>
                          {row.sample}
                        </span>
                        <span className="block text-xs text-text-muted">
                          {timeAgo(row.createdAt)}
                          {row.durationSeconds ? ` / ${duration}` : ""}
                        </span>
                        {/* A report kept from a run that failed after it was
                            built, marked as the analysis header marks it. */}
                        {row.incompleteReason && (
                          <span className="block text-xs text-status-orange">{row.incompleteReason}</span>
                        )}
                      </span>
                    </span>
                    {row.verdict && (
                      <span className={`text-xs ${verdictTone(row.verdict).text}`}>
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
                    <span className={`flex items-center gap-1.5 ${badge.text}`}>
                      <span aria-hidden="true" className={`w-1.5 h-1.5 rounded-full ${badge.dot}`} />
                      <span className="text-xs font-medium">{row.status}</span>
                    </span>
                  </Link>
                  <RowActions
                    row={row}
                    onCancel={() => {
                      setCancelError(null);
                      setConfirmJob(row);
                    }}
                  />
                </div>
              );
            })
          )}
        </div>
        <ShowMoreRows shown={Math.min(shown, filtered.length)} total={filtered.length} onShow={setShown} />
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
              <h3 id="cancel-job-title" className="text-sm font-semibold text-text-primary">Cancel analysis</h3>
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
              Cancelling analysis {confirmJob.id.slice(0, 8)} stops it where it is and
              marks it cancelled. It cannot be undone.
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
                {cancelling ? "Cancelling..." : "Cancel analysis"}
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
