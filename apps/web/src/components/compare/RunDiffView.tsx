"use client";

import Link from "next/link";
import { useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  CircleAlert,
  CircleCheck,
  CircleHelp,
  Equal,
  Minus,
  Pencil,
  Plus,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import EvidenceChips from "@/components/analysis/EvidenceChips";
import Th from "@/components/ui/Th";
import { formatDateTime } from "@/lib/report-utils";
import type { DiffRow, DiffSection, DiffSide, DiffStatus, RunDiff } from "@/types/runDiff";
import {
  cappedNote,
  countsSentence,
  differenceCount,
  groupSections,
  sideLines,
  STATUS_META,
  statusWord,
  visibleRows,
} from "./runDiff";

/** Rows drawn per section before "Show all": a large bundle with unchanged
 *  rows shown would otherwise put tens of thousands of rows in the page. */
const ROW_LIMIT = 200;

const STATUS_ICON: Record<DiffStatus, LucideIcon> = {
  changed: Pencil,
  added: Plus,
  removed: Minus,
  only_in_a: ArrowLeft,
  only_in_b: ArrowRight,
  unchanged: Equal,
};

/** A status as an icon, a printed mark and a word: readable without colour. */
function StatusBadge({ row }: { row: DiffRow }) {
  const status = row.status;
  const meta = STATUS_META[status];
  const Icon = STATUS_ICON[status];
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded border px-1.5 py-0.5 text-xs ${meta.tone}`}
    >
      <Icon size={16} aria-hidden="true" />
      <span aria-hidden="true" className="font-mono">
        {meta.mark}
      </span>
      {statusWord(row)}
    </span>
  );
}

function SideCard({ label, side }: { label: string; side: DiffSide }) {
  return (
    <div className="min-w-0 flex-1 rounded border border-border bg-bg-surface p-3">
      <div className="text-[11px] uppercase tracking-wider text-text-muted">Run {label}</div>
      <div
        className="truncate text-sm font-semibold text-text-primary print:whitespace-normal print:break-all"
        title={side.file_name ?? ""}
      >
        {side.file_name || "File name not recorded"}
      </div>
      <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
        <dt className="text-text-muted">Run</dt>
        <dd className="min-w-0 truncate font-mono print:whitespace-normal print:break-all">
          <Link href={`/analysis/${side.job_id}`} className="text-accent-strong hover:underline">
            {side.job_id}
          </Link>
        </dd>
        <dt className="text-text-muted">Analysed</dt>
        <dd>{side.created_at ? formatDateTime(side.created_at) : "not recorded"}</dd>
        <dt className="text-text-muted">SHA-256</dt>
        <dd className="min-w-0 break-all font-mono text-text-secondary">
          {side.sha256 ?? "not recorded"}
        </dd>
      </dl>
    </div>
  );
}

function SampleStatement({ diff }: { diff: RunDiff }) {
  const Icon = diff.same_sample === true ? CircleCheck : diff.same_sample === false ? CircleAlert : CircleHelp;
  const word =
    diff.same_sample === true ? "Same file" : diff.same_sample === false ? "Different files" : "Not known";
  return (
    <p className="flex items-start gap-2 text-sm text-text-primary">
      <Icon size={16} aria-hidden="true" className="mt-0.5 shrink-0 text-text-secondary" />
      <span>
        <strong className="font-semibold">{word}.</strong> {diff.sample_statement}
      </span>
    </p>
  );
}

/** One side of a row: the fields that differ on a changed row, every field otherwise. */
function SideCell({ row, side }: { row: DiffRow; side: "a" | "b" }) {
  if (!row[side]) return <span className="text-text-muted">No such row</span>;
  const lines = sideLines(row, side);
  return (
    <ul className="space-y-0.5">
      {lines.map((line, i) => (
        <li key={i} className="break-words">
          {line}
        </li>
      ))}
    </ul>
  );
}

function SectionTable({
  section,
  rows,
  diff,
}: {
  section: DiffSection;
  rows: DiffRow[];
  diff: RunDiff;
}) {
  return (
    <div className="overflow-x-auto print:overflow-visible">
      <table className="w-full text-xs">
        <caption className="sr-only">
          {section.title}: rows paired by {section.match_key}
        </caption>
        <thead className="border-b border-border">
          <tr>
            <Th>Status</Th>
            <Th>Row</Th>
            <Th>Run A</Th>
            <Th>Run B</Th>
            <Th>Evidence</Th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={`${row.key}-${i}`} className="border-b border-border-light align-top break-inside-avoid">
              <td className="px-4 py-2">
                <StatusBadge row={row} />
              </td>
              <th scope="row" className="px-4 py-2 text-left font-normal text-text-primary break-words max-w-xs">
                {row.label}
                {row.note && <div className="mt-0.5 text-[11px] text-text-muted">{row.note}</div>}
              </th>
              <td className="px-4 py-2 text-text-secondary">
                <SideCell row={row} side="a" />
              </td>
              <td className="px-4 py-2 text-text-secondary">
                <SideCell row={row} side="b" />
              </td>
              <td className="px-4 py-2">
                {row.evidence.a.length === 0 && row.evidence.b.length === 0 ? (
                  <span className="text-text-muted">none cited</span>
                ) : (
                  <div className="space-y-1">
                    {row.evidence.a.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1">
                        <span className="text-[11px] text-text-muted">A</span>
                        <EvidenceChips ids={row.evidence.a} jobId={diff.a.job_id} />
                      </div>
                    )}
                    {row.evidence.b.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1">
                        <span className="text-[11px] text-text-muted">B</span>
                        <EvidenceChips ids={row.evidence.b} jobId={diff.b.job_id} />
                      </div>
                    )}
                  </div>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function SectionBlock({
  section,
  diff,
  showUnchanged,
}: {
  section: DiffSection;
  diff: RunDiff;
  showUnchanged: boolean;
}) {
  const [showAll, setShowAll] = useState(false);
  const all = visibleRows(section, showUnchanged);
  const rows = showAll ? all : all.slice(0, ROW_LIMIT);
  const headingId = `diff-${section.key}-heading`;
  const { a: evA, b: evB } = section.section_evidence ?? { a: [], b: [] };
  return (
    <section
      id={`diff-${section.key}`}
      aria-labelledby={headingId}
      className="mb-4 rounded border border-border bg-bg-surface break-inside-avoid-page"
    >
      <div className="border-b border-border px-4 py-2.5">
        <h3 id={headingId} className="text-sm font-semibold text-text-primary">
          {section.title}{" "}
          <span className="font-normal text-text-secondary">({countsSentence(section.counts)})</span>
        </h3>
        <p className="mt-0.5 text-[11px] text-text-muted">Paired by {section.match_key}.</p>
        {section.notes.map((note) => (
          <p key={note} className="mt-1 text-[11px] text-status-orange">
            {note}
          </p>
        ))}
        {(evA.length > 0 || evB.length > 0) && (
          <div className="mt-1 space-y-1 text-[11px] text-text-muted">
            <div>Section evidence, cited for the section as a whole rather than for one row:</div>
            {evA.length > 0 && (
              <div className="flex flex-wrap items-center gap-1">
                <span>A</span>
                <EvidenceChips ids={evA} jobId={diff.a.job_id} />
              </div>
            )}
            {evB.length > 0 && (
              <div className="flex flex-wrap items-center gap-1">
                <span>B</span>
                <EvidenceChips ids={evB} jobId={diff.b.job_id} />
              </div>
            )}
          </div>
        )}
      </div>
      {rows.length > 0 ? (
        <>
          <SectionTable section={section} rows={rows} diff={diff} />
          {cappedNote(rows.length, all.length) && (
            <p className="hidden px-4 py-2 text-xs text-text-secondary print:block">
              {cappedNote(rows.length, all.length)}
            </p>
          )}
          {all.length > rows.length && (
            <div className="px-4 py-2 print:hidden">
              <button
                type="button"
                onClick={() => setShowAll(true)}
                className="rounded border border-border px-2 py-0.5 text-xs text-text-secondary hover:border-text-muted hover:text-text-primary"
              >
                Show all {all.length} rows ({all.length - rows.length} more)
              </button>
            </div>
          )}
        </>
      ) : (
        <p className="px-4 py-3 text-xs text-text-muted">
          {section.rows.length === 0
            ? "Neither run's record holds a row here."
            : "No differences. Show unchanged rows to list them."}
        </p>
      )}
    </section>
  );
}

/** The whole diff: who was compared with whom, then every section in order. */
export default function RunDiffView({ diff }: { diff: RunDiff }) {
  const [showUnchanged, setShowUnchanged] = useState(false);
  const grouped = groupSections(diff.sections);

  return (
    <div className="run-diff">
      <div className="mb-3 flex flex-col gap-3 md:flex-row">
        <SideCard label="A" side={diff.a} />
        <SideCard label="B" side={diff.b} />
      </div>
      <div className="mb-4 rounded border border-border bg-bg-surface p-3">
        <SampleStatement diff={diff} />
        <p className="mt-1 text-xs text-text-secondary">
          Each run&apos;s record is stated as stored. Nothing here says which run is right.
          {" "}In total: {countsSentence(diff.totals)}.
        </p>
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-4 print:hidden">
        <label className="inline-flex items-center gap-2 text-xs text-text-secondary">
          <input
            type="checkbox"
            checked={showUnchanged}
            onChange={(e) => setShowUnchanged(e.target.checked)}
            className="accent-accent"
          />
          Show unchanged rows
        </label>
      </div>

      <nav aria-label="Sections" className="mb-4 print:hidden">
        <ul className="flex flex-wrap gap-2">
          {diff.sections.map((s) => (
            <li key={s.key}>
              <a
                href={`#diff-${s.key}`}
                className="inline-flex items-center gap-1 rounded border border-border px-2 py-0.5 text-xs text-text-secondary hover:border-text-muted hover:text-text-primary"
              >
                {s.title}
                <span className="font-mono text-text-muted">{differenceCount(s.counts)}</span>
                <span className="sr-only">differences</span>
              </a>
            </li>
          ))}
        </ul>
      </nav>

      {grouped.map(([group, sections]) => (
        <div key={group}>
          <h2 className="mb-2 mt-5 text-xs font-semibold uppercase tracking-wider text-text-muted">
            {group}
          </h2>
          {sections.map((section) => (
            <SectionBlock
              key={section.key}
              section={section}
              diff={diff}
              showUnchanged={showUnchanged}
            />
          ))}
        </div>
      ))}
    </div>
  );
}
