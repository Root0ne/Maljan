/**
 * How the run diff reads on the page, kept apart from the page so it can be
 * tested without a browser.
 *
 * Nothing here compares anything: the API paired the rows and decided each
 * status. This module only orders, filters and words what the API sent.
 */

import type { JobDTO } from "@/lib/api";
import type {
  DiffRow,
  DiffSection,
  DiffStatus,
  DiffValue,
} from "@/types/runDiff";

export interface StatusMeta {
  /** The word a reader sees; the status is never carried by colour alone. */
  label: string;
  /** A one-character mark printed beside the word, which survives a
   *  black-and-white print. */
  mark: string;
  /** Text and border classes from the console tokens. */
  tone: string;
}

export const STATUS_META: Record<DiffStatus, StatusMeta> = {
  changed: { label: "Changed", mark: "~", tone: "text-status-orange border-status-orange/40" },
  added: { label: "Added in B", mark: "+", tone: "text-status-green border-status-green/40" },
  removed: { label: "Removed in B", mark: "−", tone: "text-status-red border-status-red/40" },
  only_in_a: { label: "Only in A", mark: "A", tone: "text-status-blue border-status-blue/40" },
  only_in_b: { label: "Only in B", mark: "B", tone: "text-status-purple border-status-purple/40" },
  unchanged: { label: "Unchanged", mark: "=", tone: "text-text-muted border-border" },
};

/** The order rows are listed in: what differs first, what is the same last. */
export const STATUS_ORDER: readonly DiffStatus[] = [
  "changed",
  "added",
  "removed",
  "only_in_a",
  "only_in_b",
  "unchanged",
];

const RANK: Record<DiffStatus, number> = Object.fromEntries(
  STATUS_ORDER.map((status, index) => [status, index]),
) as Record<DiffStatus, number>;

/** The rows a section shows, differences first, the record's order kept within a status. */
export function visibleRows(section: DiffSection, showUnchanged: boolean): DiffRow[] {
  return section.rows
    .map((row, index) => ({ row, index }))
    .filter(({ row }) => showUnchanged || row.status !== "unchanged")
    .sort((x, y) => RANK[x.row.status] - RANK[y.row.status] || x.index - y.index)
    .map(({ row }) => row);
}

/** How many rows of a section differ in any way. */
export function differenceCount(counts: Record<DiffStatus, number>): number {
  return STATUS_ORDER.filter((s) => s !== "unchanged").reduce((n, s) => n + (counts[s] ?? 0), 0);
}

/** The section's counts in words, differences only, or a plain statement of none. */
export function countsSentence(counts: Record<DiffStatus, number>): string {
  const parts = STATUS_ORDER.filter((s) => s !== "unchanged" && (counts[s] ?? 0) > 0).map(
    (s) => `${counts[s]} ${STATUS_META[s].label.toLowerCase()}`,
  );
  if (parts.length === 0) {
    return counts.unchanged > 0 ? `No differences in ${counts.unchanged} rows` : "Nothing recorded";
  }
  return parts.join(", ");
}

/** One recorded value as text. Absent is said to be absent, never printed as blank. */
export function formatValue(value: DiffValue | undefined): string {
  if (value === null || value === undefined || value === "") return "not recorded";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.length === 0 ? "none" : value.map(formatValue).join(", ");
  return JSON.stringify(value);
}

/** Field names read better in words than as keys. */
const FIELD_WORDS: Record<string, string> = { stated_by: "who stated it" };

/** A field name as a reader reads it. */
export function fieldLabel(name: string): string {
  return FIELD_WORDS[name] ?? name.replace(/_/g, " ");
}

/**
 * The status word for a row. A changed row names what changed, so a row whose
 * only change is who stated a value cannot be read as a change of the value.
 */
export function statusWord(row: DiffRow): string {
  if (row.status !== "changed" || row.changes.length === 0) return STATUS_META[row.status].label;
  return `Changed: ${row.changes.map((c) => fieldLabel(c.field)).join(", ")}`;
}

/**
 * One side of a row as `name: value` lines. On a changed row every field is
 * listed, and a field equal in both runs says so, so the value that did not
 * change stays in view beside the one that did.
 */
export function sideLines(row: DiffRow, side: "a" | "b"): string[] {
  const fields = row[side];
  if (!fields) return [];
  if (row.status !== "changed") return fieldLines(fields);
  const changed = new Set(row.changes.map((c) => c.field));
  return Object.entries(fields).map(([name, value]) =>
    changed.has(name)
      ? `${fieldLabel(name)}: ${formatValue(value)}`
      : `${fieldLabel(name)}: ${formatValue(value)} (same in both)`,
  );
}

/** What a printed section says when it holds fewer rows than the section has. */
export function cappedNote(shown: number, total: number): string | null {
  if (shown >= total) return null;
  return `Showing ${shown} of ${total} rows; open the page and choose Show all to see the rest.`;
}

/** A side's fields as `name: value` lines, for a row that one run alone holds. */
export function fieldLines(fields: Record<string, DiffValue> | null): string[] {
  if (!fields) return [];
  return Object.entries(fields).map(([name, value]) => `${fieldLabel(name)}: ${formatValue(value)}`);
}

/** Sections grouped under their group heading, in the order the API sent them. */
export function groupSections(sections: readonly DiffSection[]): Array<[string, DiffSection[]]> {
  const groups = new Map<string, DiffSection[]>();
  for (const section of sections) {
    const list = groups.get(section.group) ?? [];
    list.push(section);
    groups.set(section.group, list);
  }
  return [...groups.entries()];
}

/** The completed runs of the same sample, newest first, without the run itself. */
export function siblingRuns(jobs: readonly JobDTO[], self: JobDTO | null): JobDTO[] {
  if (!self) return [];
  return jobs
    .filter((j) => j.id !== self.id && j.status === "completed")
    .filter(
      (j) =>
        j.sample_id === self.sample_id ||
        (!!self.sample_sha256 && j.sample_sha256 === self.sample_sha256),
    )
    .sort((x, y) => (x.created_at < y.created_at ? 1 : -1));
}

/**
 * Completed runs matching what the reader typed: a run id, a file name or a
 * digest, without regard to case. An empty query lists them all.
 */
export function searchRuns(jobs: readonly JobDTO[], query: string, selfId: string): JobDTO[] {
  const q = query.trim().toLowerCase();
  return jobs.filter((j) => {
    if (j.id === selfId || j.status !== "completed") return false;
    if (!q) return true;
    return [j.id, j.sample_filename ?? "", j.sample_sha256 ?? ""].some((v) =>
      v.toLowerCase().includes(q),
    );
  });
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Whether the reader typed a whole run id, which can be compared without a match in the list. */
export function isRunId(value: string): boolean {
  return UUID_RE.test(value.trim());
}
