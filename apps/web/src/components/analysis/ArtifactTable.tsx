"use client";

import type { EvidenceSection } from "@/types/malware-report";
import EvidenceChips from "./EvidenceChips";
import { saysSomething } from "./reportSections";

/**
 * One report section, drawn from its own declared shape.
 *
 * The point of this component is that it knows nothing about malware. A
 * section says whether it is a table, a key/value block, a list or a
 * paragraph, and carries the ledger entries it was built from; that is enough
 * to render it, which is what lets a tool server nobody has written yet reach
 * the console without a line of code here changing.
 *
 * The citation chips are not decoration. They are the difference between a
 * table of facts and a table of assertions: every row above them came out of
 * the calls they name, and each chip opens that call.
 */
export default function ArtifactTable({ section }: { section: EvidenceSection }) {
  const rows = rowsOf(section);
  /* A section whose every row said nothing is not drawn at all: a heading over
   * an empty table is the "No X yet" placeholder in another shape. */
  if (section.kind === "kv" && rows.length === 0) return null;
  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex flex-wrap items-center gap-2">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          {section.title || section.key}
        </h2>
        <span className="text-[10px] font-mono text-text-muted">{section.key}</span>
        <span className="ml-auto flex items-center gap-2">
          {section.evidence_ids.length === 0 && section.source && (
            <span className="text-[10px] uppercase tracking-wider text-text-muted">
              {section.source}
            </span>
          )}
          <EvidenceChips ids={section.evidence_ids} />
        </span>
      </div>
      <SectionBody section={section} rows={rows} />
    </div>
  );
}

/**
 * The rows a section draws.
 *
 * A key/value row whose value is nothing is a field the tool has rather than a
 * fact about the sample, so it is not drawn. A table row is left alone: its
 * cells are positional, and dropping one because a column is blank would put
 * the rest under the wrong headings.
 */
function rowsOf(section: EvidenceSection): string[][] {
  const rows = section.rows ?? [];
  if (section.kind !== "kv") return rows;
  return rows.filter((row) => row.slice(1).some(saysSomething));
}

function SectionBody({ section, rows }: { section: EvidenceSection; rows: string[][] }) {
  if (section.kind === "table" || (section.kind === "kv" && rows.length > 0)) {
    const columns =
      section.columns.length > 0
        ? section.columns
        : section.kind === "kv"
        ? ["Field", "Value"]
        : rows[0]?.map((_, i) => `Column ${i + 1}`) ?? [];
    if (rows.length === 0) {
      return <p className="p-4 text-xs text-text-muted">The tool returned no rows.</p>;
    }
    return (
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              {columns.map((column) => (
                <th
                  key={column}
                  className="px-4 py-2 text-left text-[10px] font-medium uppercase tracking-wider text-text-muted"
                >
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border-light">
            {rows.map((row, i) => (
              <tr key={i} className="hover:bg-bg-hover">
                {row.map((cell, j) => (
                  <td
                    key={j}
                    className="px-4 py-2 text-xs font-mono text-text-secondary break-all align-top"
                  >
                    {cell || "-"}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  if (section.kind === "list") {
    return (
      <ul className="p-4 space-y-1">
        {section.items.map((item, i) => (
          <li key={i} className="text-xs font-mono text-text-secondary break-all">
            {item}
          </li>
        ))}
      </ul>
    );
  }

  return (
    <p className="p-4 text-xs text-text-secondary leading-relaxed whitespace-pre-wrap break-words">
      {section.text}
    </p>
  );
}

/** Every section one tab claims, or nothing at all when it claims none. */
export function ArtifactSections({ sections }: { sections: EvidenceSection[] }) {
  if (sections.length === 0) return null;
  return (
    <>
      {sections.map((section) => (
        <ArtifactTable key={section.key} section={section} />
      ))}
    </>
  );
}
