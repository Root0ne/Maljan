"use client";

import { Fragment, useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { EvidenceEntry } from "@/types/evidence";
import {
  EMPTY_OPTIONS,
  EVIDENCE_PAGE_SIZE,
  NO_FILTERS,
  argsDetail,
  argsSummary,
  deepLinkView,
  evidenceQuery,
  formatCallDuration,
  mergeOptions,
  outputPreview,
  pageCount,
  withFilter,
  type EvidenceFilters,
} from "./evidenceRows";

/**
 * The evidence ledger: one row per tool call the run made.
 *
 * This is the surface that makes the rest of the console checkable. Every
 * section of the report cites the entry ids it was built from, and a citation
 * is only a citation if it resolves — so a chip anywhere in the report links
 * here with `?evidence=ev_0007`, and this opens that row and scrolls to it.
 *
 * Rows are never assembled from the report. They come from the ledger
 * endpoint, which is the record of what the tools were actually asked and what
 * they actually returned, including the calls that failed and the outputs that
 * were trimmed to an agent's byte budget. A row that says a call failed is as
 * much of a finding as one that says it worked.
 */
export default function EvidencePanel({ jobId }: { jobId: string }) {
  const searchParams = useSearchParams();
  const deepLink = searchParams?.get("evidence") ?? "";

  const initial = deepLinkView(deepLink);
  const [filters, setFilters] = useState<EvidenceFilters>(initial?.filters ?? NO_FILTERS);
  const [page, setPage] = useState(initial?.page ?? 1);
  const [entries, setEntries] = useState<EvidenceEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [options, setOptions] = useState(EMPTY_OPTIONS);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<Set<string>>(() => new Set(initial ? [deepLink] : []));
  const [fullOutput, setFullOutput] = useState<Set<string>>(new Set());
  const [fullArgs, setFullArgs] = useState<Set<string>>(new Set());
  const rowRefs = useRef<Record<string, HTMLTableRowElement | null>>({});

  // A citation followed from another tab arrives as a change of URL under a
  // panel that is already mounted, so the view is adjusted during the render
  // that sees the new id rather than in an effect after it. Tracking the id
  // this panel last obeyed is what keeps the adjustment to that one render:
  // paging or filtering away from a deep link must not be undone.
  const [obeyed, setObeyed] = useState(deepLink);
  if (deepLink !== obeyed) {
    setObeyed(deepLink);
    const view = deepLinkView(deepLink);
    if (view) {
      setFilters(view.filters);
      setPage(view.page);
      setOpen((current) => new Set(current).add(deepLink));
    }
  }

  // Which page, under which filters, the rows on screen belong to. `loading`
  // is derived from it rather than stored, so no state is set on the way into
  // a fetch and a stale page can never read as a fresh one.
  const wanted = JSON.stringify(evidenceQuery(filters, page));
  const [loaded, setLoaded] = useState<string | null>(null);
  const loading = loaded !== wanted;

  useEffect(() => {
    let cancelled = false;
    api
      .getJobEvidence(jobId, evidenceQuery(filters, page))
      .then((response) => {
        if (cancelled) return;
        setEntries(response.entries);
        setTotal(response.total);
        setOptions((current) => mergeOptions(current, response.entries));
        setError(null);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setEntries([]);
        setError(getErrorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setLoaded(wanted);
      });
    return () => {
      cancelled = true;
    };
  }, [jobId, filters, page, wanted]);

  // Scrolling waits for the page the entry is on to be rendered, which is why
  // it keys on the rows rather than on the link.
  useEffect(() => {
    if (!deepLink || loading) return;
    const row = rowRefs.current[deepLink];
    if (row) row.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [deepLink, loading, entries]);

  const toggle = (setter: typeof setOpen, id: string) =>
    setter((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const setFilter = (field: keyof EvidenceFilters, value: string) => {
    const next = withFilter(filters, field, value);
    setFilters(next.filters);
    setPage(next.page);
  };

  const pages = pageCount(total);
  const filtered = Boolean(filters.stage || filters.agent || filters.tool);

  return (
    <div className="space-y-3">
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border flex flex-wrap items-center gap-3">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Evidence Ledger
          </h2>
          <span className="text-[11px] text-text-muted">
            {total} {total === 1 ? "call" : "calls"}
            {filtered ? " matching" : ""}
          </span>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            {(["stage", "agent", "tool"] as const).map((field) => (
              <label key={field} className="flex items-center gap-1 text-[11px]">
                <span className="text-text-muted uppercase tracking-wider">{field}</span>
                <select
                  aria-label={`Filter by ${field}`}
                  className="bg-bg-deep border border-border rounded px-2 py-1 text-xs text-text-primary focus:outline-none focus:border-accent"
                  value={filters[field]}
                  onChange={(e) => setFilter(field, e.target.value)}
                >
                  <option value="">all</option>
                  {options[field].map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </label>
            ))}
            {filtered && (
              <button
                type="button"
                className="text-[11px] text-text-secondary hover:text-text-primary"
                onClick={() => {
                  setFilters(NO_FILTERS);
                  setPage(1);
                }}
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {error && (
          <p className="px-4 py-3 text-xs text-status-red" role="alert">
            The ledger could not be read: {error}
          </p>
        )}

        {!error && (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wider text-text-muted border-b border-border">
                  <th className="px-3 py-2 font-medium">ID</th>
                  <th className="px-3 py-2 font-medium">Stage</th>
                  <th className="px-3 py-2 font-medium">Agent</th>
                  <th className="px-3 py-2 font-medium">Server</th>
                  <th className="px-3 py-2 font-medium">Tool</th>
                  <th className="px-3 py-2 font-medium">Arguments</th>
                  <th className="px-3 py-2 font-medium text-right">Duration</th>
                  <th className="px-3 py-2 font-medium">Result</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => {
                  const expanded = open.has(entry.entry_id);
                  const summary = argsSummary(entry.args);
                  const showAllArgs = fullArgs.has(entry.entry_id);
                  const preview = outputPreview(entry.output, fullOutput.has(entry.entry_id));
                  const cited = deepLink === entry.entry_id;
                  return (
                    <Fragment key={entry.entry_id}>
                      <tr
                        ref={(node) => {
                          rowRefs.current[entry.entry_id] = node;
                        }}
                        className={`border-b border-border-light cursor-pointer hover:bg-bg-hover transition-colors ${
                          cited ? "bg-accent/5" : ""
                        }`}
                        onClick={() => toggle(setOpen, entry.entry_id)}
                      >
                        <td className="px-3 py-2">
                          <button
                            type="button"
                            aria-expanded={expanded}
                            aria-label={`Toggle ${entry.entry_id}`}
                            className="font-mono text-accent-strong"
                            onClick={(e) => {
                              e.stopPropagation();
                              toggle(setOpen, entry.entry_id);
                            }}
                          >
                            {entry.entry_id}
                          </button>
                        </td>
                        <td className="px-3 py-2 text-text-secondary">{entry.stage}</td>
                        <td className="px-3 py-2 text-text-primary">{entry.agent}</td>
                        <td className="px-3 py-2 text-text-muted">
                          {entry.server ?? "built-in"}
                        </td>
                        <td className="px-3 py-2 font-mono text-text-primary break-all">
                          {entry.tool}
                        </td>
                        <td className="px-3 py-2 font-mono text-text-muted break-all">
                          {summary.text || "\u2014"}
                        </td>
                        <td className="px-3 py-2 text-right text-text-secondary tabular-nums">
                          {formatCallDuration(entry.duration_ms)}
                        </td>
                        <td
                          className={`px-3 py-2 text-[10px] uppercase tracking-wider ${
                            entry.ok ? "text-status-green" : "text-status-red"
                          }`}
                        >
                          {entry.ok ? "ok" : "error"}
                        </td>
                      </tr>
                      {expanded && (
                        <tr className="border-b border-border-light bg-bg-deep">
                          <td colSpan={8} className="px-3 pb-3 pt-1 space-y-3">
                            {summary.truncated && (
                              <button
                                type="button"
                                className="text-[11px] text-text-secondary hover:text-text-primary"
                                onClick={() => toggle(setFullArgs, entry.entry_id)}
                              >
                                {showAllArgs ? "Hide arguments" : "Show all arguments"}
                              </button>
                            )}
                            {(showAllArgs || !summary.truncated) && entry.args && (
                              <div>
                                <h3 className="text-[10px] uppercase tracking-wider text-text-muted mb-1">
                                  Arguments
                                </h3>
                                <pre className="text-[11px] text-text-secondary overflow-auto max-h-64 whitespace-pre-wrap break-all">
                                  {argsDetail(entry.args)}
                                </pre>
                              </div>
                            )}
                            <div>
                              <h3 className="text-[10px] uppercase tracking-wider text-text-muted mb-1">
                                Output
                              </h3>
                              {entry.output ? (
                                <>
                                  <pre className="text-[11px] text-text-secondary overflow-auto max-h-96 whitespace-pre-wrap break-all">
                                    {preview.text}
                                  </pre>
                                  {preview.hidden > 0 && (
                                    <button
                                      type="button"
                                      className="text-[11px] text-text-secondary hover:text-text-primary"
                                      onClick={() => toggle(setFullOutput, entry.entry_id)}
                                    >
                                      Show more ({preview.hidden} more characters)
                                    </button>
                                  )}
                                  {preview.hidden === 0 && fullOutput.has(entry.entry_id) && (
                                    <button
                                      type="button"
                                      className="text-[11px] text-text-secondary hover:text-text-primary"
                                      onClick={() => toggle(setFullOutput, entry.entry_id)}
                                    >
                                      Show less
                                    </button>
                                  )}
                                </>
                              ) : (
                                <p className="text-[11px] text-text-muted">
                                  The output was dropped to keep this agent inside its byte
                                  budget. The call, its arguments and its result stand.
                                </p>
                              )}
                            </div>
                            {entry.structured != null && (
                              <div>
                                <h3 className="text-[10px] uppercase tracking-wider text-text-muted mb-1">
                                  Structured
                                </h3>
                                <pre className="text-[11px] text-text-secondary overflow-auto max-h-96 whitespace-pre-wrap break-all">
                                  {JSON.stringify(entry.structured, null, 2)}
                                </pre>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
                {entries.length === 0 && (
                  <tr>
                    <td colSpan={8} className="px-3 py-6 text-center text-text-muted">
                      {loading
                        ? "Reading the ledger\u2026"
                        : filtered
                        ? "No call on this run matches these filters."
                        : "This run recorded no tool calls."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        <div className="px-4 py-2 border-t border-border flex items-center gap-3 text-[11px] text-text-muted">
          <span>
            Page {page} of {pages}
          </span>
          <button
            type="button"
            className="text-text-secondary hover:text-text-primary disabled:opacity-40"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Previous
          </button>
          <button
            type="button"
            className="text-text-secondary hover:text-text-primary disabled:opacity-40"
            disabled={page >= pages}
            onClick={() => setPage((p) => Math.min(pages, p + 1))}
          >
            Next
          </button>
          <span className="ml-auto">{EVIDENCE_PAGE_SIZE} per page</span>
        </div>
      </div>
    </div>
  );
}
