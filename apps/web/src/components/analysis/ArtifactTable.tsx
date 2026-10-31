"use client";

import type { EvidenceSection } from "@/types/malware-report";
import { humaniseKey } from "@/lib/humanise";
import EvidenceChips, { CitedText } from "./EvidenceChips";
import { saysSomething } from "./reportSections";
import { headedTable, withoutConstantColumns } from "./tableColumns";

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
export default function ArtifactTable({
  section,
  showKey = false,
}: {
  section: EvidenceSection;
  /** Print the section's key beside its title. Only the Evidence tab, where a
   *  reader checks the work, says which key a section was built under; the
   *  findings tabs give it its title alone. */
  showKey?: boolean;
}) {
  const rows = rowsOf(section);
  /* A section whose every row said nothing is not drawn at all: a heading over
   * an empty table is the "No X yet" placeholder in another shape.
   *
   * Its rows are not all it may carry, though. A section is keyed by the tool
   * that built it and a tool that answered twice in two shapes contributes to
   * one section, so a `kv` section can hold items or text as well; the section
   * goes only when it holds nothing at all. */
  if (section.kind === "kv" && rows.length === 0 && !hasOtherContent(section)) return null;
  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex flex-wrap items-center gap-2">
        <h2 className="text-sm font-semibold text-text-primary">{sectionTitle(section)}</h2>
        {showKey && <span className="text-[10px] font-mono text-text-muted">{section.key}</span>}
        <span className="ml-auto flex items-center gap-2">
          {section.evidence_ids.length === 0 && section.source && (
            <span className="text-[11px] text-text-muted">{section.source}</span>
          )}
          <EvidenceChips ids={section.evidence_ids} />
        </span>
      </div>
      <SectionBody section={section} rows={rows} />
    </div>
  );
}

/**
 * What a section is titled.
 *
 * A tool that named its section keeps its name. One that did not has a title
 * derived from its key on the way out — "Ioc", "Ioc count" — and that is read
 * back here, alongside the key fallback for a section with no title at all.
 * The derivation is recognised rather than assumed: a title is only re-read
 * when it is what reading the key would have produced anyway, so a title
 * somebody wrote keeps every capital they put in it.
 */
function sectionTitle(section: EvidenceSection): string {
  const key = humaniseKey(section.key);
  const title = (section.title ?? "").trim();
  if (!title) return key;
  return title.toLowerCase() === key.toLowerCase() ? key : title;
}

/** Whether the section carries anything besides its rows. */
function hasOtherContent(section: EvidenceSection): boolean {
  return (section.items?.length ?? 0) > 0 || Boolean((section.text ?? "").trim());
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
  return rows.filter(
    (row) =>
      !Array.isArray(row) ||
      row.slice(1).some((cell) => saysSomething(typeof cell === "string" ? cell : String(cell ?? ""))),
  );
}

/**
 * Everything a section carries, whatever its declared kind.
 *
 * The kind says how the section is mainly drawn, not what else it holds. A
 * table whose tool cut it short says so in its `text` ("18 more rows not
 * shown here; the evidence endpoint carries every one under ev_0005"), a list
 * of the functions examined leads with a sentence counting them, and a `kv`
 * section a tool answered twice into can hold items or text beside its rows.
 * Drawing only the part the kind names dropped the rest without a trace, so
 * the rows, the items and the text are each drawn when present, in that
 * order.
 */
function SectionBody({ section, rows }: { section: EvidenceSection; rows: string[][] }) {
  const items = (section.items ?? []).filter(
    (item) => typeof item === "string" && item.trim().length > 0,
  );
  const text = typeof section.text === "string" ? section.text : "";
  const hasText = text.trim().length > 0;
  /* A `kv` section that kept no row draws whatever else it carries, which is
   * how a tool that answered once with a dict and once with prose still shows
   * the prose. A table with no row says so only when it carries nothing else
   * either. */
  const drawsTable = rows.length > 0;
  const saysNoRows =
    section.kind === "table" && rows.length === 0 && items.length === 0 && !hasText;
  return (
    <>
      {drawsTable && <SectionTable section={section} rows={rows} />}
      {saysNoRows && <p className="p-4 text-xs text-text-muted">The tool returned no rows.</p>}
      {items.length > 0 && (
        <ul className={`p-4 space-y-1 ${drawsTable ? "border-t border-border-light" : ""}`}>
          {items.map((item, i) => (
            <li key={i} className="text-xs font-mono text-text-secondary break-all">
              {item}
            </li>
          ))}
        </ul>
      )}
      {hasText && (
        <p
          className={`p-4 text-xs text-text-secondary leading-relaxed whitespace-pre-wrap break-words ${
            drawsTable || items.length > 0 ? "border-t border-border-light" : ""
          }`}
        >
          <CitedText text={text} />
        </p>
      )}
    </>
  );
}

function SectionTable({ section, rows }: { section: EvidenceSection; rows: string[][] }) {
  /* Column headers come from the tool, so they arrive as whatever key it
     used: `optional_dependency` and `technique_ids` sat beside the
     hand-written "Rule category" of the table below. Read back rather than
     renamed — the console does not know what a tool's columns mean, only
     how a key is spelled. Every cell gets a heading: a row wider than the
     declared columns adds its own (`headedTable`). */
  const headed = headedTable(
    section.columns?.length ? section.columns : section.kind === "kv" ? ["Field", "Value"] : [],
    rows,
  );
  const declared = headed.columns.map(humaniseKey);
  /* Only a real table: a key/value block's two columns are its field names
     and its values, and lifting "Value: yes" out of a two-row block would
     leave a list of fields with no answers beside them. */
  const narrowed =
    section.kind === "table"
      ? withoutConstantColumns(declared, headed.rows)
      : { columns: declared, rows: headed.rows, constants: [], empty: [] };
  return (
    <>
      {(narrowed.constants.length > 0 || narrowed.empty.length > 0) && (
        <p className="px-4 pt-3 text-[11px] text-text-muted">
          {/* A constant column can be the evidence one (`Evidence: ev_0006`):
              cited as every other id is, never printed bare. */}
          <CitedText
            text={
              narrowed.constants.map((c) => `${c.column}: ${c.value}`).join(" · ") +
              (narrowed.constants.length > 0 && narrowed.empty.length > 0 ? " · " : "") +
              (narrowed.empty.length > 0 ? `${narrowed.empty.join(", ")}: nothing on any row` : "") +
              " — the same on every row below."
            }
          />
        </p>
      )}
      <div
        role="region"
        tabIndex={0}
        aria-label={`${sectionTitle(section)} table, scrolls sideways`}
        className="overflow-x-auto focus-visible:outline focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-accent"
      >
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              {narrowed.columns.map((column, i) => (
                <th
                  key={i}
                  scope="col"
                  className="px-4 py-2 text-left text-xs font-medium text-text-muted"
                >
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border-light">
            {narrowed.rows.map((row, i) => (
              <tr key={i} className="hover:bg-bg-hover">
                {row.map((cell, j) => (
                  <td
                    key={j}
                    /* A cell of several lines — a decompiled function, a
                       listing — keeps its lines: run together, a
                       decompiler's `undefined8 FUN_…(undefined8 param_1)`
                       read like the console printing a missing value. */
                    className={`px-4 py-2 text-xs font-mono text-text-secondary break-all align-top ${
                      cell.includes("\n") ? "whitespace-pre-wrap" : ""
                    }`}
                  >
                    {/* A cell naming records (`ev_0019, ev_0024`) cites
                        them: drawn the way every citation is. */}
                    {cell ? /\bev_\d+\b/.test(cell) ? <CitedText text={cell} /> : cell : "-"}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

/** Every section one tab claims, or nothing at all when it claims none. */
export function ArtifactSections({
  sections,
  showKey = false,
}: {
  sections: EvidenceSection[];
  showKey?: boolean;
}) {
  if (sections.length === 0) return null;
  return (
    <>
      {sections.map((section) => (
        <ArtifactTable key={section.key} section={section} showKey={showKey} />
      ))}
    </>
  );
}
