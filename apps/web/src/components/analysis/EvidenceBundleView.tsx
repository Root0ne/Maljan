"use client";

import { useEffect, useMemo, useState, useSyncExternalStore } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import { ApiError, getErrorMessage } from "@/lib/errors";
import { formatCallDuration } from "./evidenceRows";
import { analysisHref } from "./overview";
import SafeMarkdown from "./SafeMarkdown";
import {
  INDEX_ANCHOR,
  INDEX_RESULTS,
  NOTES_ANCHOR,
  NO_INDEX_FILTERS,
  filterIndex,
  filtersActive,
  indexAgents,
  navEntries,
  notesCiting,
  readBundle,
  resolveTarget,
  subsectionAnchors,
  type BundleIndexRow,
  type BundleNote,
  type EvidenceBundle,
  type IndexFilters,
  type IndexResult,
} from "./evidenceBundle";

/**
 * The evidence bundle, read in the console: the record behind the analyst
 * report, with the same anchors as the bundle's own HTML.
 *
 * A sections navigator on the left (a picker on a narrow screen) and one
 * section at a time on the right, so a reader moves through the record the
 * way its contents list reads. The evidence index is drawn from the
 * bundle's rows, searchable and filterable, each row a link to the call's
 * full output under Records; the notes the report cites list the entries
 * each rests on. Every place has its address: `#ev_0007` opens the index on
 * that row, `#cite-3` the notes on that note, `#sec-…` a section or the
 * section a subsection is in, so a link copied from the bundle lands here.
 */

/** How many index rows are drawn before "show more". */
const INDEX_STEP = 100;

function subscribeHash(onChange: () => void): () => void {
  window.addEventListener("hashchange", onChange);
  return () => window.removeEventListener("hashchange", onChange);
}

/** The URL fragment, followed as it changes. */
function useHash(): string {
  return useSyncExternalStore(subscribeHash, () => window.location.hash, () => "");
}

type Loaded = { bundle: EvidenceBundle } | { problem: string } | { absent: true } | null;

/* One request per report: a remount (strict mode, the report refetching under
 * the view) joins the one in flight, and a server that answered "no such
 * endpoint" is not asked again while the page stays open. */
const inFlight = new Map<string, Promise<string>>();
const absentFor = new Set<string>();

function fetchBundle(reportId: string): Promise<string> {
  if (absentFor.has(reportId)) return Promise.reject(new ApiError("not available", 404));
  let pending = inFlight.get(reportId);
  if (!pending) {
    pending = api.getReportEvidenceBundleJson(reportId).catch((err: unknown) => {
      if (err instanceof ApiError && err.status === 404) absentFor.add(reportId);
      throw err;
    });
    inFlight.set(reportId, pending);
    const forget = () => inFlight.delete(reportId);
    pending.then(forget, forget);
  }
  return pending;
}

export default function EvidenceBundleView({ jobId, reportId }: { jobId: string; reportId: string }) {
  const [loaded, setLoaded] = useState<Loaded>(null);
  const [loadedFor, setLoadedFor] = useState<string | null>(null);
  const hash = useHash();

  useEffect(() => {
    let live = true;
    fetchBundle(reportId)
      .then((body) => {
        if (live) setLoaded(readBundle(body));
      })
      .catch((err: unknown) => {
        if (!live) return;
        if (err instanceof ApiError && err.status === 404) setLoaded({ absent: true });
        else setLoaded({ problem: getErrorMessage(err) || "the server did not answer" });
      })
      .finally(() => {
        if (live) setLoadedFor(reportId);
      });
    return () => {
      live = false;
    };
  }, [reportId]);

  const bundle = loaded && "bundle" in loaded ? loaded.bundle : null;
  const entries = useMemo(() => (bundle ? navEntries(bundle) : []), [bundle]);
  const subsections = useMemo(() => (bundle ? subsectionAnchors(bundle.sections) : new Map<string, string[]>()), [bundle]);
  const target = resolveTarget(hash, entries, subsections);
  const current = target?.section ?? entries[0]?.anchor ?? "";
  const focus = target?.focus ?? null;

  // A followed link brings its place into view once the section it is in is
  // drawn; the bare page keeps the reader where they are.
  const followed = target ? target.focus ?? target.section : null;
  useEffect(() => {
    if (!bundle || !followed) return;
    const frame = requestAnimationFrame(() => {
      document.getElementById(followed)?.scrollIntoView({ block: "start" });
    });
    return () => cancelAnimationFrame(frame);
  }, [bundle, followed]);

  const recordsHref = `${analysisHref(jobId, "evidence")}/records`;

  if (loadedFor !== reportId || loaded === null) {
    return <p className="text-sm text-text-secondary">Reading the evidence bundle&hellip;</p>;
  }
  if (!bundle) {
    const absent = "absent" in loaded;
    return (
      <div
        role={absent ? "status" : "alert"}
        data-testid={absent ? "evidence-bundle-absent" : undefined}
        className={
          absent
            ? "rounded-md border border-border bg-bg-surface px-4 py-3 text-sm"
            : "rounded-md border border-status-red/30 bg-status-red/5 px-4 py-3 text-sm"
        }
      >
        {absent ? (
          <p className="text-text-primary">The evidence bundle is not available from this server.</p>
        ) : (
          <p className="text-status-red">The evidence bundle could not be read: {"problem" in loaded ? loaded.problem : ""}.</p>
        )}
        <p className="mt-1 text-text-secondary">
          Every tool call is still listed under{" "}
          <Link href={recordsHref} className="text-accent-strong underline">
            Records
          </Link>
          .
        </p>
      </div>
    );
  }
  if (entries.length === 0) {
    return <p className="text-sm text-text-muted">Not found: this bundle holds no sections.</p>;
  }

  const at = Math.max(0, entries.findIndex((e) => e.anchor === current));
  const entry = entries[at];
  const section = bundle.sections.find((s) => s.anchor === entry.anchor);
  const go = (anchor: string) => {
    window.location.hash = anchor;
  };

  return (
    <div className="grid gap-4 lg:grid-cols-[15rem_minmax(0,1fr)]" data-testid="evidence-bundle">
      <div className="min-w-0">
        <label className="flex flex-col gap-1 text-xs text-text-secondary lg:hidden">
          Section
          <select
            value={entry.anchor}
            onChange={(e) => go(e.target.value)}
            className="w-full rounded border border-border bg-bg-surface px-2 py-1.5 text-sm text-text-primary"
          >
            {entries.map((e) => (
              <option key={e.anchor} value={e.anchor}>
                {e.title}
                {e.count != null ? ` (${e.count})` : ""}
              </option>
            ))}
          </select>
        </label>
        <nav
          aria-label="Bundle sections"
          className="hidden lg:sticky lg:top-44 lg:block lg:max-h-[calc(100vh-12rem)] lg:overflow-y-auto"
        >
          <ol className="space-y-0.5 border-l border-border text-sm">
            {entries.map((e) => {
              const on = e.anchor === entry.anchor;
              return (
                <li key={e.anchor}>
                  <a
                    href={`#${e.anchor}`}
                    aria-current={on ? "location" : undefined}
                    className={`-ml-px flex items-center justify-between gap-2 border-l-2 py-1 pl-3 pr-1 ${
                      on
                        ? "border-accent font-medium text-text-primary"
                        : "border-transparent text-text-secondary hover:border-border hover:text-text-primary"
                    }`}
                  >
                    <span className="min-w-0 break-words">{e.title}</span>
                    {e.count != null && <span className="shrink-0 text-[11px] text-text-muted">{e.count}</span>}
                  </a>
                </li>
              );
            })}
          </ol>
        </nav>
      </div>

      <section aria-labelledby={entry.anchor} className="min-w-0 rounded-md border border-border bg-bg-surface">
        <div className="flex flex-wrap items-baseline justify-between gap-2 border-b border-border-light px-4 py-2.5">
          <h2 id={entry.anchor} className="scroll-mt-40 text-sm font-semibold text-text-primary">
            {entry.title}
          </h2>
          <span className="text-[11px] text-text-muted">
            Section {at + 1} of {entries.length}
          </span>
        </div>
        <div className="px-4 py-3">
          {entry.anchor === INDEX_ANCHOR ? (
            <BundleIndex
              rows={bundle.evidence_index}
              notes={bundle.notes}
              focus={focus}
              recordsHref={recordsHref}
            />
          ) : entry.anchor === NOTES_ANCHOR ? (
            <BundleNotes notes={bundle.notes} index={bundle.evidence_index} focus={focus} />
          ) : section && section.markdown.trim() ? (
            <SafeMarkdown
              markdown={section.markdown}
              subsectionIds={subsections.get(section.anchor) ?? []}
              skipFirstHeading
            />
          ) : (
            <p className="text-sm text-text-muted">Not found</p>
          )}
        </div>
        <div className="flex flex-wrap justify-between gap-2 border-t border-border-light px-4 py-2 text-xs">
          {at > 0 ? (
            <a href={`#${entries[at - 1].anchor}`} className="text-accent-strong hover:underline">
              &larr; {entries[at - 1].title}
            </a>
          ) : (
            <span />
          )}
          {at < entries.length - 1 && (
            <a href={`#${entries[at + 1].anchor}`} className="text-accent-strong hover:underline">
              {entries[at + 1].title} &rarr;
            </a>
          )}
        </div>
      </section>
    </div>
  );
}

function resultWords(row: BundleIndexRow): { text: string; tone: string } {
  if (!row.ok) return { text: "failed", tone: "text-status-red" };
  if (row.repeated_of !== null) return { text: `same as ${row.repeated_of}`, tone: "text-text-secondary" };
  if (row.truncated) return { text: "ok, trimmed", tone: "text-status-orange" };
  return { text: "ok", tone: "text-status-green" };
}

/** The evidence index: one row per tool call, searchable, each row's output one link away. */
function BundleIndex({
  rows,
  notes,
  focus,
  recordsHref,
}: {
  rows: readonly BundleIndexRow[];
  notes: readonly BundleNote[];
  focus: string | null;
  recordsHref: string;
}) {
  const [filters, setFilters] = useState<IndexFilters>(NO_INDEX_FILTERS);
  const [shown, setShown] = useState(INDEX_STEP);
  const agents = useMemo(() => indexAgents(rows), [rows]);
  const kept = useMemo(() => filterIndex(rows, filters), [rows, filters]);
  const active = filtersActive(filters);
  // A followed id is always drawn: the list is long enough to reach it.
  const focusAt = focus ? kept.findIndex((r) => r.id === focus) : -1;
  const count = Math.max(shown, focusAt + 1);
  const hiddenByFilters = focus !== null && focusAt === -1 && rows.some((r) => r.id === focus);
  const set = (patch: Partial<IndexFilters>) => {
    setFilters((f) => ({ ...f, ...patch }));
    setShown(INDEX_STEP);
  };

  if (rows.length === 0) return <p className="text-sm text-text-muted">Not found: this run recorded no tool calls.</p>;

  return (
    <div className="space-y-3">
      <p className="text-xs text-text-secondary">
        Every tool call the run made, in the order it was made. A row&apos;s id is what the report cites; its output is
        under Records.
      </p>
      <div className="flex flex-wrap items-end gap-2">
        <label className="flex min-w-0 flex-1 basis-48 flex-col gap-1 text-xs text-text-secondary">
          Search the index
          <input
            type="search"
            value={filters.query}
            onChange={(e) => set({ query: e.target.value })}
            placeholder="Id, agent, server or tool"
            className="w-full rounded border border-border bg-bg-deep px-2 py-1 text-sm text-text-primary"
          />
        </label>
        <label className="flex flex-col gap-1 text-xs text-text-secondary">
          Agent
          <select
            value={filters.agent}
            onChange={(e) => set({ agent: e.target.value })}
            className="rounded border border-border bg-bg-deep px-2 py-1 text-sm text-text-primary"
          >
            <option value="">Every agent</option>
            {agents.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-xs text-text-secondary">
          Result
          <select
            value={filters.result}
            onChange={(e) => set({ result: e.target.value as IndexResult })}
            className="rounded border border-border bg-bg-deep px-2 py-1 text-sm text-text-primary"
          >
            {INDEX_RESULTS.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </label>
        {active && (
          <button type="button" onClick={() => set(NO_INDEX_FILTERS)} className="pb-1.5 text-xs text-accent-strong hover:underline">
            Clear filters
          </button>
        )}
      </div>
      <p role="status" className="text-[11px] text-text-muted">
        {active ? `${kept.length} of ${rows.length} calls match` : `${rows.length} calls`}
      </p>
      {hiddenByFilters && (
        <p className="text-xs text-status-orange">
          {focus} is in the index but hidden by these filters.{" "}
          <button type="button" onClick={() => set(NO_INDEX_FILTERS)} className="text-accent-strong hover:underline">
            Clear filters
          </button>
        </p>
      )}
      {kept.length === 0 ? (
        <p className="text-sm text-text-muted">Not found: no call matches these filters.</p>
      ) : (
        <div className="rounded border border-border-light">
          <table className="w-full table-fixed text-xs">
            <thead className="bg-bg-deep">
              <tr className="border-b border-border-light text-left text-text-muted">
                <th scope="col" className="w-[5.5rem] px-2 py-1.5 font-medium">Id</th>
                <th scope="col" className="hidden w-[18%] px-2 py-1.5 font-medium sm:table-cell">Agent</th>
                <th scope="col" className="px-2 py-1.5 font-medium">Tool</th>
                <th scope="col" className="w-[22%] px-2 py-1.5 font-medium">Result</th>
                <th scope="col" className="hidden w-20 px-2 py-1.5 text-right font-medium md:table-cell">Duration</th>
                <th scope="col" className="hidden w-24 px-2 py-1.5 font-medium lg:table-cell">Cited in</th>
                <th scope="col" className="w-16 px-2 py-1.5">
                  <span className="sr-only">Output</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {kept.slice(0, count).map((row) => {
                const result = resultWords(row);
                const citing = notesCiting(notes, row.id);
                return (
                  <tr
                    key={row.id}
                    id={row.id}
                    className={`scroll-mt-40 border-b border-border-light align-top last:border-b-0 ${
                      focus === row.id ? "bg-accent/10" : ""
                    }`}
                  >
                    <td className="px-2 py-1.5 font-mono text-text-primary">{row.id}</td>
                    <td className="hidden px-2 py-1.5 break-words text-text-secondary sm:table-cell">{row.agent}</td>
                    <td className="px-2 py-1.5 font-mono break-words [overflow-wrap:anywhere] text-text-primary">
                      {row.tool}
                      {row.server && row.server !== row.agent && (
                        <span className="block font-sans text-[11px] text-text-muted">{row.server}</span>
                      )}
                    </td>
                    <td className={`px-2 py-1.5 break-words ${result.tone}`}>{result.text}</td>
                    <td className="hidden px-2 py-1.5 text-right tabular-nums text-text-secondary md:table-cell">
                      {formatCallDuration(row.duration_ms)}
                    </td>
                    <td className="hidden px-2 py-1.5 lg:table-cell">
                      {citing.length === 0 ? (
                        <span className="text-text-muted">&mdash;</span>
                      ) : (
                        citing.map((n, i) => (
                          <span key={n.number}>
                            {i > 0 && ", "}
                            <a href={`#${n.anchor}`} className="text-accent-strong hover:underline" aria-label={`Note ${n.number}`}>
                              {n.number}
                            </a>
                          </span>
                        ))
                      )}
                    </td>
                    <td className="px-2 py-1.5">
                      <Link
                        href={`${recordsHref}?evidence=${encodeURIComponent(row.id)}`}
                        className="text-accent-strong hover:underline"
                        aria-label={`Output of ${row.id}`}
                      >
                        Output
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {kept.length > count && (
            <div className="flex flex-wrap items-center gap-3 border-t border-border-light px-2 py-1.5 text-[11px] text-text-muted">
              <span>
                Showing {count} of {kept.length}.
              </span>
              <button type="button" onClick={() => setShown(count + INDEX_STEP)} className="text-accent-strong hover:underline">
                Show {Math.min(INDEX_STEP, kept.length - count)} more
              </button>
              <button type="button" onClick={() => setShown(kept.length)} className="text-accent-strong hover:underline">
                Show all
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** The notes the analyst report cites, each with the entries it rests on. */
function BundleNotes({
  notes,
  index,
  focus,
}: {
  notes: readonly BundleNote[];
  index: readonly BundleIndexRow[];
  focus: string | null;
}) {
  const indexed = useMemo(() => new Set(index.map((r) => r.id)), [index]);
  if (notes.length === 0) return <p className="text-sm text-text-muted">Not found: the analyst report cites no evidence entry.</p>;
  return (
    <div className="space-y-3">
      <p className="text-xs text-text-secondary">
        Each numbered note of the analyst report, the section it stands in, and the evidence entries it rests on.
      </p>
      <ol className="space-y-1 text-sm">
        {notes.map((note) => (
          <li
            key={note.anchor}
            id={note.anchor}
            className={`scroll-mt-40 rounded px-2 py-1 ${focus === note.anchor ? "bg-accent/10" : ""}`}
          >
            <span className="font-medium text-text-primary">Note {note.number}</span>
            {note.section && <span className="text-text-muted"> ({note.section})</span>}
            <span className="text-text-muted">: </span>
            {note.evidence_ids.map((id, i) => (
              <span key={id}>
                {i > 0 && ", "}
                {indexed.has(id) ? (
                  <a href={`#${id}`} className="font-mono text-xs text-accent-strong hover:underline">
                    {id}
                  </a>
                ) : (
                  <span className="font-mono text-xs text-text-secondary" title="No entry of the evidence index carries this id">
                    {id} (not in the index)
                  </span>
                )}
              </span>
            ))}
          </li>
        ))}
      </ol>
    </div>
  );
}
