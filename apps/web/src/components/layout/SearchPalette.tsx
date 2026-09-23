"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import type { JobDTO, ReportSummaryDTO, SampleDTO } from "@/lib/api";
import { analysisRows } from "@/lib/analyses";
import { timeAgo } from "@/lib/report-utils";
import { verdictLabel, verdictTone } from "@/lib/verdict";
import { getErrorMessage } from "@/lib/errors";

/* ── Types ─────────────────────────────────────────────── */

/* Two groups, because there are two kinds of thing to find: a file, and what
 * was concluded about it. A report used to be a third group whose rows linked
 * exactly where the job rows linked — the same analysis, offered twice, one
 * above the other. */
type ResultGroup = "samples" | "analyses";

interface ResultItem {
  group: ResultGroup;
  key: string;
  primary: string;
  secondary: string;
  badge?: string;
  badgeClass?: string;
  href: string;
}

/** The DOM id of one result row, which is what `aria-activedescendant` names. */
export function optionId(key: string): string {
  return `search-result-${key}`;
}

interface SearchPaletteProps {
  open: boolean;
  query: string;
  onClose: () => void;
  /**
   * Called after a result is selected (post-navigation).
   * Lets the parent clear the input value if it chooses to.
   */
  onSelect?: () => void;
  /**
   * The id of the row the arrow keys are on, or `null` when there is none.
   *
   * The combobox is on the header's input, not here, and `aria-activedescendant`
   * has to sit on the element that holds the focus — so the palette reports the
   * highlight and the input announces it. Without this the arrow keys moved a
   * background colour and told a screen reader nothing (WCAG 4.1.2).
   */
  onActiveChange?: (id: string | null) => void;
}

/* ── Helpers ───────────────────────────────────────────── */

/* Keyed by the shared bucket, not the raw string. The
 * backend emits "Malware", which was not a key here — every malicious report's
 * badge silently fell through to the muted "unknown" grey. */
function verdictClass(verdict: string | null): string {
  return verdictTone(verdict).text;
}

/** How a run that has not produced a verdict yet is badged. */
const STATUS_CLASS: Record<string, string> = {
  completed: "text-status-green",
  failed: "text-status-red",
  running: "text-status-orange",
};

function ci(haystack: string | null | undefined, needle: string): boolean {
  if (!haystack) return false;
  return haystack.toLowerCase().includes(needle);
}

/* ── Component ─────────────────────────────────────────── */

export default function SearchPalette({
  open,
  query,
  onClose,
  onSelect,
  onActiveChange,
}: SearchPaletteProps) {
  const router = useRouter();
  const containerRef = useRef<HTMLDivElement>(null);

  const [samples, setSamples] = useState<SampleDTO[]>([]);
  const [jobs, setJobs] = useState<JobDTO[]>([]);
  const [reports, setReports] = useState<ReportSummaryDTO[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeIndex, setActiveIndex] = useState(0);
  const [debouncedQuery, setDebouncedQuery] = useState("");

  // ``handleSelect`` was declared
  // BELOW the ``Enter``-key useEffect that called it, which the React
  // Compiler / ESLint ``react-hooks/immutability`` rule flags as
  // access-before-declared (the inner closure was bound when the effect
  // mounted, not when handleSelect ran). Hoisting the function above
  // the useEffect lets the effect's closure see the real function on
  // every render rather than relying on TDZ-aware lexical scoping
  // (which the React Compiler explicitly does not honour).
  const handleSelect = (r: ResultItem) => {
    router.push(r.href);
    onClose();
    onSelect?.();
  };

  /* Debounce the incoming query (200 ms). */
  useEffect(() => {
    const id = window.setTimeout(() => setDebouncedQuery(query.trim()), 200);
    return () => window.clearTimeout(id);
  }, [query]);

  /* Reset highlight whenever the effective query changes. */
  // Reset the keyboard highlight on every
  // debounced-query change. Derived state is not viable — the highlight
  // is itself stateful (arrow keys mutate it), so the only way to reset
  // it on a new query is an effect setState.
  useEffect(() => {
    setActiveIndex(0);
  }, [debouncedQuery]);

  /* Fetch in parallel once the palette opens & the query is non-empty. */
  useEffect(() => {
    if (!open) return;
    if (!debouncedQuery) {
      // The empty-query branch clears stale
      // results from the previous query so the dropdown collapses
      // immediately. The state IS derived (an empty query maps to an
      // empty list) but the source of truth — the debounced query —
      // lives in another effect, so cross-effect reset via setState
      // is the cleanest path.
      setSamples([]);
      setJobs([]);
      setReports([]);
      setError(null);
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    // Each source used to be
    // swallowed into an empty list, so an unreachable API rendered as a
    // confident "No matches". Track which sources failed and say so.
    Promise.all([
      api.getSamples(1, 50).catch((e: unknown) => e as Error),
      api.getJobs(1, 50).catch((e: unknown) => e as Error),
      api.getReports(1, 50).catch((e: unknown) => e as Error),
    ])
      .then(([s, j, r]) => {
        if (cancelled) return;
        const failed: string[] = [];
        if (s instanceof Error) failed.push("samples");
        else setSamples(s.items ?? []);
        if (j instanceof Error) failed.push("jobs");
        else setJobs(j.items ?? []);
        if (r instanceof Error) failed.push("reports");
        else setReports(r.items ?? []);
        setError(
          failed.length === 0
            ? null
            : failed.length === 3
              ? "Search unavailable — could not reach the API."
              : `Search is incomplete — ${failed.join(", ")} could not be loaded.`,
        );
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(`Search unavailable — ${getErrorMessage(err)}`);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open, debouncedQuery]);

  /* Compute filtered, grouped results. */
  const results = useMemo<ResultItem[]>(() => {
    const q = debouncedQuery.toLowerCase();
    if (!q) return [];

    const sampleMatches: ResultItem[] = samples
      .filter(
        (s) =>
          ci(s.original_filename, q) ||
          ci(s.sha256, q) ||
          ci(s.md5, q)
      )
      .slice(0, 8)
      .map((s) => ({
        group: "samples",
        key: `sample-${s.id}`,
        primary: s.original_filename || s.sha256,
        secondary: s.sha256,
        href: `/samples?sample=${encodeURIComponent(s.id)}`,
      }));

    /* The job knows the status and the run knows the verdict, so a row is
     * searchable by either: type "ransomware" or "failed" and the same list
     * answers. */
    const analysisMatches: ResultItem[] = analysisRows(jobs, reports)
      .filter(
        (row) =>
          ci(row.id, q) ||
          ci(row.sampleId, q) ||
          ci(row.sample, q) ||
          ci(row.verdict, q) ||
          ci(verdictLabel(row.verdict), q) ||
          ci(row.malwareCategory, q) ||
          ci(row.status, q),
      )
      .slice(0, 8)
      .map((row) => ({
        group: "analyses",
        key: `analysis-${row.id}`,
        primary: row.sample,
        // The verdict is the badge. Eight runs of one file were eight
        // identical rows, each stating its verdict twice — once in grey
        // mixed case and once in colour, uppercase — with nothing to tell
        // one run from another. What differs is when it ran and which run
        // it is, so that is what the secondary line carries.
        secondary: [
          row.createdAt ? timeAgo(row.createdAt) : "",
          row.malwareCategory,
          row.id.slice(0, 8),
        ]
          .filter(Boolean)
          .join(" · "),
        badge: row.verdict ? verdictLabel(row.verdict) : row.status,
        badgeClass: row.verdict ? verdictClass(row.verdict) : STATUS_CLASS[row.status] ?? "text-text-muted",
        href: `/analysis/${row.id}`,
      }));

    return [...sampleMatches, ...analysisMatches];
  }, [debouncedQuery, samples, jobs, reports]);

  /* Group result rows for rendering. */
  const grouped = useMemo(() => {
    const out: Record<ResultGroup, ResultItem[]> = {
      samples: [],
      analyses: [],
    };
    for (const r of results) out[r.group].push(r);
    return out;
  }, [results]);

  /* Keyboard navigation. */
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (results.length === 0) return;
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setActiveIndex((i) => (i + 1) % results.length);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setActiveIndex((i) => (i - 1 + results.length) % results.length);
      } else if (e.key === "Enter") {
        e.preventDefault();
        const target = results[activeIndex];
        if (target) handleSelect(target);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, results, activeIndex, onClose]);

  /* Tell the combobox which row it is pointing at. */
  useEffect(() => {
    const active = open ? results[activeIndex] : undefined;
    onActiveChange?.(active ? optionId(active.key) : null);
  }, [open, results, activeIndex, onActiveChange]);

  /* Click outside closes. */
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      const node = containerRef.current;
      if (!node) return;
      if (!node.contains(e.target as Node)) onClose();
    };
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [open, onClose]);

  if (!open) return null;

  /* Compute the absolute index for each row for highlighting. */
  let runningIndex = -1;
  const groupOrder: ResultGroup[] = ["samples", "analyses"];
  const groupLabel: Record<ResultGroup, string> = {
    samples: "Samples",
    analyses: "Analyses",
  };

  const hasResults = results.length > 0;
  const showEmpty = !debouncedQuery;
  const showNoMatch = !!debouncedQuery && !loading && !hasResults && !error;

  return (
    <div
      ref={containerRef}
      id="global-search-palette"
      className="absolute left-0 right-0 top-full mt-1 z-50 bg-bg-surface border border-border rounded shadow-lg overflow-hidden"
      role="listbox"
      aria-label="Search results"
    >
      {showEmpty && (
        <div className="px-3 py-3 text-xs text-text-muted">
          Type to search samples and analyses.
        </div>
      )}

      {error && (
        <div role="alert" className="px-3 py-3 text-xs text-status-red">
          {error}
        </div>
      )}

      {loading && !hasResults && !showEmpty && (
        <div className="px-3 py-3 text-xs text-text-muted">Searching...</div>
      )}

      {showNoMatch && (
        <div className="px-3 py-3 text-xs text-text-muted">
          No matches for <span className="text-text-secondary">«{debouncedQuery}»</span>
        </div>
      )}

      {hasResults && (
        <div className="max-h-[60vh] overflow-y-auto py-1">
          {groupOrder.map((group) => {
            const items = grouped[group];
            if (items.length === 0) return null;
            return (
              <div key={group} className="py-1">
                <div className="px-3 py-1 text-[11px] uppercase tracking-wider text-text-muted">
                  {groupLabel[group]}
                </div>
                {items.map((r) => {
                  runningIndex += 1;
                  const isActive = runningIndex === activeIndex;
                  return (
                    <button
                      key={r.key}
                      id={optionId(r.key)}
                      type="button"
                      role="option"
                      aria-selected={isActive}
                      onMouseEnter={() => setActiveIndex(results.indexOf(r))}
                      onMouseDown={(e) => {
                        // Prevent input blur before click handler fires.
                        e.preventDefault();
                      }}
                      onClick={() => handleSelect(r)}
                      className={`w-full h-8 flex items-center gap-3 px-3 text-left ${
                        isActive ? "bg-bg-hover" : ""
                      }`}
                    >
                      <span className="flex-1 min-w-0 truncate text-xs text-text-primary">
                        {r.primary}
                      </span>
                      <span className="hidden sm:block truncate text-[11px] text-text-muted font-mono max-w-[40%]">
                        {r.secondary}
                      </span>
                      {r.badge && (
                        <span
                          className={`text-[11px] uppercase tracking-wider ${
                            r.badgeClass ?? "text-text-muted"
                          }`}
                        >
                          {r.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
