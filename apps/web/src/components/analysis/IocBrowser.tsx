"use client";

import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import { useMemo, useState } from "react";

import CopyButton from "@/components/ui/CopyButton";
import Drawer from "@/components/ui/Drawer";
import Section from "@/components/ui/Section";
import ShowMoreRows from "@/components/ui/ShowMoreRows";
import Th from "@/components/ui/Th";
import type { MalwareReport } from "@/types/malware-report";
import { CitedText } from "./EvidenceChips";
import type { Decision } from "./indicators";
import {
  EXPORT_STATE_WORDS,
  IOC_ROWS_STEP,
  exportCounts,
  exportState,
  filterIocs,
  iocFacets,
  iocRows,
  relatedFindings,
  sortedForReading,
  type ExportState,
  type IocRow,
  type PublicationFilter,
} from "./iocList";

/* A state no row is in is not offered as a filter. */
const STATES: ExportState[] = ["published", "withheld", "unanswered", "not-in-table"];

/**
 * Every indicator the report holds, in one list (`iocList.ts`): type
 * facets with their counts, a search, the export decision as a filter, and a
 * table ten rows at a time with a copy control on each value. A value opens
 * in the side panel with the export's decision and its reason, whether the
 * verdict names it, and what else the report says about it.
 */
export default function IocBrowser({ mr }: { mr: MalwareReport | null | undefined }) {
  const tableRows = useMemo(() => iocRows(mr), [mr]);
  const facets = useMemo(() => iocFacets(tableRows), [tableRows]);
  const rows = useMemo(() => sortedForReading(tableRows), [tableRows]);
  const [type, setType] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [publication, setPublication] = useState<PublicationFilter>("all");
  const [shown, setShown] = useState(IOC_ROWS_STEP);
  const [detail, setDetail] = useState<{ row: IocRow; opener: HTMLElement } | null>(null);

  const filtered = filterIocs(rows, { type, query, publication });
  const counts = exportCounts(rows);
  const present = STATES.filter((st) => counts[st] > 0);

  return (
    <Section title="Indicators" count={rows.length || null} empty={rows.length === 0}>
      <div className="space-y-3" data-testid="indicators-panel">
        <div className="flex flex-wrap items-center gap-2">
          <input
            type="search"
            aria-label="Search indicators"
            placeholder="Search indicators"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setShown(IOC_ROWS_STEP);
            }}
            className="h-7 w-56 max-w-full rounded border border-border bg-bg-deep px-2.5 text-xs text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none"
          />
          <select
            aria-label="Export decision"
            value={publication}
            onChange={(e) => {
              setPublication(e.target.value as PublicationFilter);
              setShown(IOC_ROWS_STEP);
            }}
            className="h-7 rounded border border-border bg-bg-deep px-2 text-xs text-text-primary"
          >
            <option value="all">Any export decision</option>
            {present.map((st) => (
              <option key={st} value={st}>
                {EXPORT_STATE_WORDS[st][0].toUpperCase() + EXPORT_STATE_WORDS[st].slice(1)}
              </option>
            ))}
          </select>
          <span className="text-[11px] text-text-muted">
            {present.map((st) => `${counts[st]} ${EXPORT_STATE_WORDS[st]}`).join(" · ")}
          </span>
        </div>
        <div role="group" aria-label="Indicator type" className="flex flex-wrap gap-1">
          {[{ type: null as string | null, count: rows.length }, ...facets].map((f) => (
            <button
              key={f.type ?? "all"}
              type="button"
              aria-pressed={type === f.type}
              onClick={() => {
                setType(f.type);
                setShown(IOC_ROWS_STEP);
              }}
              className={`rounded border px-2 py-0.5 text-[11px] ${
                type === f.type ? "border-accent text-accent-strong" : "border-border text-text-secondary hover:text-text-primary"
              }`}
            >
              {f.type ?? "All"} {f.count}
            </button>
          ))}
        </div>

        {filtered.length === 0 ? (
          <p className="text-xs text-text-muted">No indicator matches.</p>
        ) : (
          <div {...scrollRegion("Indicators")} className={`-mx-4 overflow-x-auto ${SCROLL_REGION_FOCUS}`}>
            <table className="w-full">
              <thead>
                <tr className="border-y border-border-light">
                  <Th>Type</Th>
                  <Th>Value</Th>
                  <Th>Source</Th>
                  <Th>Export</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-light">
                {filtered.slice(0, shown).map((row) => (
                  <tr key={row.key} className="align-top hover:bg-bg-hover">
                    <td className="whitespace-nowrap px-4 py-2 text-xs text-text-muted">{row.type || "-"}</td>
                    <td className="px-4 py-2">
                      <span className="flex items-start gap-2">
                        <button
                          type="button"
                          onClick={(e) => setDetail({ row, opener: e.currentTarget })}
                          className="min-w-0 text-left font-mono text-xs text-status-blue break-all hover:underline"
                        >
                          {row.value}
                        </button>
                        <CopyButton value={row.value} what={`indicator ${row.value}`} />
                      </span>
                      {row.context && <div className="mt-0.5 text-[11px] text-text-muted break-words">{row.context}</div>}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 text-xs text-text-secondary">{row.source || "-"}</td>
                    <td className="px-4 py-2">
                      <PublicationBadge row={row} />
                      {row.inVerdict && <span className="ml-1.5 text-[11px] text-text-muted">· in the verdict</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <ShowMoreRows shown={Math.min(shown, filtered.length)} total={filtered.length} onShow={setShown} step={IOC_ROWS_STEP} />
          </div>
        )}
      </div>

      <Drawer
        open={detail !== null}
        title={detail ? `${detail.row.type || "Indicator"}` : ""}
        onClose={() => setDetail(null)}
        returnFocusTo={detail?.opener ?? null}
      >
        {detail && <IocDetail row={detail.row} mr={mr} />}
      </Drawer>
    </Section>
  );
}

export function IocDetail({ row, mr }: { row: IocRow; mr: MalwareReport | null | undefined }) {
  const related = relatedFindings(mr, row.value);
  return (
    <div className="space-y-4 text-sm">
      <div className="flex items-start gap-2">
        <code className="min-w-0 flex-1 break-all rounded border border-border-light bg-bg-deep px-2 py-1 font-mono text-xs text-text-primary">
          {row.value}
        </code>
        <CopyButton value={row.value} what={`indicator ${row.value}`} />
      </div>
      <dl className="space-y-2">
        <Pair label="Type">
          {row.type || "-"}
          {row.kind && row.kind !== row.type ? ` (${row.kind})` : ""}
        </Pair>
        {row.source && <Pair label="Source">{row.source}</Pair>}
        {row.context && <Pair label="Context">{row.context}</Pair>}
        {row.recoveredBy && (
          <Pair label="Recovered by">
            <CitedText text={row.recoveredBy} />
          </Pair>
        )}
        <Pair label="Export">
          <PublicationBadge row={row} />
        </Pair>
        <Pair label="Why">
          <Reason decision={row.decision} />
        </Pair>
        {row.inVerdict && (
          <Pair label="Named in the verdict">
            {row.verdictEntries.length <= 1 ? (
              <>Yes{row.algorithm ? `, as ${row.algorithm}` : ""}</>
            ) : (
              /* Every entry the verdict gives the value, not only the first. */
              <ul className="space-y-0.5">
                {row.verdictEntries.map((e, i) => (
                  <li key={i}>
                    {e.kind || "indicator"}
                    {e.algorithm ? `, as ${e.algorithm}` : ""}
                  </li>
                ))}
              </ul>
            )}
          </Pair>
        )}
      </dl>
      <div>
        <h3 className="mb-1.5 text-xs font-semibold text-text-secondary">Related findings</h3>
        {related.length === 0 ? (
          <p className="text-xs text-text-muted">Not found</p>
        ) : (
          <ul className="space-y-1.5">
            {related.map((f, i) => (
              <li key={i} className="rounded border border-border-light px-2 py-1">
                <span className="block text-[11px] text-text-muted">{f.where}</span>
                <span className="break-words text-xs text-text-primary">{f.text}</span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Pair({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-text-muted">{label}</dt>
      <dd className="text-text-primary">{children}</dd>
    </div>
  );
}

function PublicationBadge({ row }: { row: IocRow }) {
  const state = exportState(row);
  if (state === "published" || state === "withheld") {
    const published = state === "published";
    return (
      <span
        className={`whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] ${
          published ? "bg-status-green/10 text-status-green" : "bg-bg-active text-text-muted"
        }`}
        title={published ? "Exported in the STIX bundle" : "Held out of the STIX bundle by the publish rule"}
      >
        {EXPORT_STATE_WORDS[state]}
      </span>
    );
  }
  return <span className="whitespace-nowrap text-[11px] italic text-text-muted">{EXPORT_STATE_WORDS[state]}</span>;
}

function Reason({ decision }: { decision: Decision | null }) {
  if (!decision) return <span className="text-text-muted">The indicator table holds no row for this value.</span>;
  if (!decision.answered) return <span className="italic text-text-muted">the publish rule recorded no answer</span>;
  if (!decision.reason) return <span className="text-text-muted">-</span>;
  return <CitedText text={decision.reason} />;
}
