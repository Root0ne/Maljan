"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { api } from "@/lib/api";
import type { JobDTO, ReportSummaryDTO, SampleDTO } from "@/lib/api";

/* ── Types ─────────────────────────────────────────────── */

type ResultGroup = "samples" | "jobs" | "reports";

interface ResultItem {
  group: ResultGroup;
  key: string;
  primary: string;
  secondary: string;
  badge?: string;
  badgeClass?: string;
  href: string;
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
}

/* ── Helpers ───────────────────────────────────────────── */

const VERDICT_CLASS: Record<string, string> = {
  malicious: "text-status-red",
  suspicious: "text-status-orange",
  benign: "text-status-green",
};

function verdictClass(verdict: string): string {
  return VERDICT_CLASS[verdict.toLowerCase()] ?? "text-text-muted";
}

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

  // Wave 10 W10-LINT-DEBT-02 (2026-05-30): ``handleSelect`` was declared
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
  // Wave 10 W10-LINT-DEBT-02: reset the keyboard highlight on every
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
      // Wave 10 W10-LINT-DEBT-02: empty-query branch clears stale
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

    Promise.all([
      api.getSamples(1, 50).catch(() => ({ items: [] as SampleDTO[] })),
      api.getJobs(1, 50).catch(() => ({ items: [] as JobDTO[] })),
      api.getReports(1, 50).catch(() => ({ items: [] as ReportSummaryDTO[] })),
    ])
      .then(([s, j, r]) => {
        if (cancelled) return;
        setSamples(s.items ?? []);
        setJobs(j.items ?? []);
        setReports(r.items ?? []);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Search failed");
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

    const sampleById = new Map<string, SampleDTO>();
    samples.forEach((s) => sampleById.set(s.id, s));

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

    const jobMatches: ResultItem[] = jobs
      .filter((j) => ci(j.id, q) || ci(j.sample_id, q))
      .slice(0, 8)
      .map((j) => ({
        group: "jobs",
        key: `job-${j.id}`,
        primary: j.id,
        secondary: `sample ${j.sample_id.slice(0, 12)}...`,
        badge: j.status,
        badgeClass:
          j.status === "completed"
            ? "text-status-green"
            : j.status === "failed"
            ? "text-status-red"
            : j.status === "running"
            ? "text-status-orange"
            : "text-text-muted",
        href: `/analysis/${j.id}`,
      }));

    const reportMatches: ResultItem[] = reports
      .filter((r) => {
        if (ci(r.verdict, q)) return true;
        if (ci(r.malware_category, q)) return true;
        if (ci(r.sample_filename, q)) return true;
        return false;
      })
      .slice(0, 8)
      .map((r) => ({
        group: "reports",
        key: `report-${r.id}`,
        primary: r.sample_filename || r.id,
        secondary: r.malware_category
          ? `${r.verdict} · ${r.malware_category}`
          : r.verdict,
        badge: r.verdict,
        badgeClass: verdictClass(r.verdict),
        href: `/analysis/${r.job_id}`,
      }));

    return [...sampleMatches, ...jobMatches, ...reportMatches];
  }, [debouncedQuery, samples, jobs, reports]);

  /* Group result rows for rendering. */
  const grouped = useMemo(() => {
    const out: Record<ResultGroup, ResultItem[]> = {
      samples: [],
      jobs: [],
      reports: [],
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
  const groupOrder: ResultGroup[] = ["samples", "jobs", "reports"];
  const groupLabel: Record<ResultGroup, string> = {
    samples: "Samples",
    jobs: "Jobs",
    reports: "Reports",
  };

  const hasResults = results.length > 0;
  const showEmpty = !debouncedQuery;
  const showNoMatch = !!debouncedQuery && !loading && !hasResults && !error;

  return (
    <div
      ref={containerRef}
      className="absolute left-0 right-0 top-full mt-1 z-50 bg-bg-surface border border-border rounded shadow-lg overflow-hidden"
      role="listbox"
    >
      {showEmpty && (
        <div className="px-3 py-3 text-xs text-text-muted">
          Type to search across samples, jobs, and reports.
        </div>
      )}

      {error && (
        <div className="px-3 py-3 text-xs text-status-red">
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
                      type="button"
                      role="option"
                      aria-selected={isActive}
                      onMouseEnter={() => setActiveIndex(results.indexOf(r))}
                      onMouseDown={(e) => {
                        // Prevent input blur before click handler fires.
                        e.preventDefault();
                      }}
                      onClick={() => handleSelect(r)}
                      className={`w-full h-8 flex items-center gap-3 px-3 text-left transition-colors ${
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
