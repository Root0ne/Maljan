/**
 * The evidence bundle, read for the console's Evidence tab.
 *
 * The bundle is the record behind the analyst report
 * (`maljan-evidence-bundle/1`, served at `/evidence-bundle.json`): the notes
 * the report cites, the evidence index (one row per tool call) and every
 * section of the single-file report as Markdown under its anchor. The
 * console draws it as the bundle's HTML does, with the same anchors, so a
 * link written for the one (`#ev_0007`, `#cite-3`, `#sec-command-and-control`)
 * lands on the same place in the other.
 */

import { inlineText, subsectionTitles } from "./safeMarkdown";

export const BUNDLE_FORMAT = "maljan-evidence-bundle/1";

/** The anchors of the two sections the console draws from the bundle's data
 *  rather than from their Markdown. */
export const INDEX_ANCHOR = "sec-evidence-index";
export const NOTES_ANCHOR = "sec-notes-cited-by-the-analyst-report";
/** The bundle's opening block: its title, the sample and the verdict line. */
export const TITLE_ANCHOR = "title";

export interface BundleNote {
  number: number;
  anchor: string;
  section: string;
  evidence_ids: string[];
}

export interface BundleIndexRow {
  id: string;
  agent: string;
  server: string | null;
  tool: string;
  ok: boolean;
  duration_ms: number;
  truncated: boolean;
  repeated_of: string | null;
}

export interface BundleSection {
  anchor: string;
  title: string;
  markdown: string;
}

export interface EvidenceBundle {
  report: { title: string; sha256: string; generated_at: string };
  notes: BundleNote[];
  evidence_index: BundleIndexRow[];
  sections: BundleSection[];
}

function str(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function rows<T>(value: unknown, read: (item: Record<string, unknown>) => T | null): T[] {
  if (!Array.isArray(value)) return [];
  return value.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const row = read(item as Record<string, unknown>);
    return row === null ? [] : [row];
  });
}

/**
 * The bundle a response body holds, or why it holds none. A body of another
 * format is refused by name rather than drawn as if it were this one; a row
 * missing its id is left out, and every other field reads as empty.
 */
export function readBundle(body: string): { bundle: EvidenceBundle } | { problem: string } {
  let data: unknown;
  try {
    data = JSON.parse(body);
  } catch {
    return { problem: "the server's answer is not JSON" };
  }
  if (!data || typeof data !== "object") return { problem: "the server's answer is not a bundle" };
  const doc = data as Record<string, unknown>;
  if (doc.format !== BUNDLE_FORMAT) {
    return { problem: `the server sent a bundle of format ${JSON.stringify(doc.format ?? null)}, not ${BUNDLE_FORMAT}` };
  }
  const report = (doc.report && typeof doc.report === "object" ? doc.report : {}) as Record<string, unknown>;
  return {
    bundle: {
      report: { title: str(report.title), sha256: str(report.sha256), generated_at: str(report.generated_at) },
      notes: rows(doc.notes, (n) => {
        const number = Number(n.number);
        if (!Number.isFinite(number)) return null;
        return {
          number,
          anchor: str(n.anchor) || `cite-${number}`,
          section: str(n.section),
          evidence_ids: Array.isArray(n.evidence_ids) ? n.evidence_ids.map(str).filter(Boolean) : [],
        };
      }),
      evidence_index: rows(doc.evidence_index, (r) => {
        const id = str(r.id);
        if (!id) return null;
        return {
          id,
          agent: str(r.agent),
          server: r.server == null ? null : str(r.server),
          tool: str(r.tool),
          ok: r.ok !== false,
          duration_ms: Number(r.duration_ms) || 0,
          truncated: r.truncated === true,
          repeated_of: r.repeated_of == null ? null : str(r.repeated_of),
        };
      }),
      sections: rows(doc.sections, (s) => {
        const anchor = str(s.anchor);
        if (!anchor) return null;
        return { anchor, title: str(s.title) || anchor, markdown: str(s.markdown) };
      }),
    },
  };
}

/* ── Anchors ──────────────────────────────────────────── */

const HEADING_NUMBER = /^(?:\d+(?:\.\d+)*\.?\s+|Appendix [A-Z]\.\s+)/;

/** The bundle's id for a heading titled `title` (`renderers/analyst.bundle_anchor`). */
export function bundleAnchor(title: string): string {
  const slug = title.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return `sec-${slug || "section"}`;
}

/** `anchor`, or the first of `anchor-2`, `anchor-3`… not taken; then taken. */
export function uniqueAnchor(anchor: string, taken: Set<string>): string {
  let unique = anchor;
  for (let n = 2; taken.has(unique); n++) unique = `${anchor}-${n}`;
  taken.add(unique);
  return unique;
}

/** A heading's title without its number and its voice tag. */
export function headingKey(text: string): string {
  return text.split(" · ", 1)[0].trim().replace(HEADING_NUMBER, "").trim();
}

/**
 * Every section's subsection anchors, in order, numbered as the bundle's HTML
 * numbers them: after every section's own anchor is taken, each subsection
 * takes its title's, the first use keeping the bare one.
 */
export function subsectionAnchors(sections: readonly BundleSection[]): Map<string, string[]> {
  const taken = new Set(sections.map((s) => s.anchor));
  const out = new Map<string, string[]>();
  for (const section of sections) {
    out.set(
      section.anchor,
      subsectionTitles(section.markdown).map((title) => uniqueAnchor(bundleAnchor(headingKey(title)), taken)),
    );
  }
  return out;
}

/** One entry of the sections navigator. */
export interface NavEntry {
  anchor: string;
  title: string;
  count?: number;
}

/**
 * The navigator's entries, in the bundle's order. The opening block is
 * called what it is to a reader; the evidence index and the notes carry
 * their counts, and either one the bundle's sections leave out while its
 * data holds rows is added at the end, so no part of the bundle is
 * unreachable.
 */
export function navEntries(bundle: EvidenceBundle): NavEntry[] {
  const entries: NavEntry[] = bundle.sections.map((s) => ({
    anchor: s.anchor,
    title: s.anchor === TITLE_ANCHOR ? "About this bundle" : headingKey(inlineText(s.title)) || s.title,
  }));
  const have = new Set(entries.map((e) => e.anchor));
  if (!have.has(INDEX_ANCHOR) && bundle.evidence_index.length > 0) {
    entries.push({ anchor: INDEX_ANCHOR, title: "Evidence index" });
  }
  if (!have.has(NOTES_ANCHOR) && bundle.notes.length > 0) {
    entries.push({ anchor: NOTES_ANCHOR, title: "Notes cited by the analyst report" });
  }
  for (const entry of entries) {
    if (entry.anchor === INDEX_ANCHOR) entry.count = bundle.evidence_index.length;
    if (entry.anchor === NOTES_ANCHOR) entry.count = bundle.notes.length;
  }
  return entries;
}

/** Where a link into the bundle lands: the section to show and the place in it. */
export interface BundleTarget {
  section: string;
  /** The element to bring into view inside the section; null for its top. */
  focus: string | null;
}

/**
 * The place a URL fragment names: an evidence id is its row of the index, a
 * note its line of the notes, a section itself, and a subsection the section
 * it is in. A fragment the bundle has no place for is null.
 */
export function resolveTarget(
  hash: string,
  entries: readonly NavEntry[],
  subsections: ReadonlyMap<string, readonly string[]>,
): BundleTarget | null {
  let id: string;
  try {
    id = decodeURIComponent(hash.replace(/^#/, "")).trim();
  } catch {
    // A fragment that does not decode names no place.
    return null;
  }
  if (!id) return null;
  if (/^ev_\d+$/.test(id)) return { section: INDEX_ANCHOR, focus: id };
  if (/^cite-\d+$/.test(id)) return { section: NOTES_ANCHOR, focus: id };
  if (entries.some((e) => e.anchor === id)) return { section: id, focus: null };
  for (const [section, anchors] of subsections) {
    if (anchors.includes(id)) return { section, focus: id };
  }
  return null;
}

/* ── The evidence index ───────────────────────────────── */

export type IndexResult = "all" | "failed" | "trimmed" | "repeated";

export interface IndexFilters {
  query: string;
  agent: string;
  result: IndexResult;
}

export const NO_INDEX_FILTERS: IndexFilters = { query: "", agent: "", result: "all" };

export const INDEX_RESULTS: readonly { value: IndexResult; label: string }[] = [
  { value: "all", label: "Any result" },
  { value: "failed", label: "Failed" },
  { value: "trimmed", label: "Trimmed" },
  { value: "repeated", label: "Answered from an earlier call" },
];

export function filtersActive(filters: IndexFilters): boolean {
  return Boolean(filters.query.trim() || filters.agent || filters.result !== "all");
}

/** The rows the filters keep: the words searched in the id, agent, server and tool. */
export function filterIndex(index: readonly BundleIndexRow[], filters: IndexFilters): BundleIndexRow[] {
  const words = filters.query.toLowerCase().split(/\s+/).filter(Boolean);
  return index.filter((row) => {
    if (filters.agent && row.agent !== filters.agent) return false;
    if (filters.result === "failed" && row.ok) return false;
    if (filters.result === "trimmed" && !row.truncated) return false;
    if (filters.result === "repeated" && row.repeated_of === null) return false;
    if (words.length === 0) return true;
    const hay = `${row.id} ${row.agent} ${row.server ?? ""} ${row.tool}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  });
}

/** The agents the index names, in the order they first called a tool. */
export function indexAgents(index: readonly BundleIndexRow[]): string[] {
  return [...new Set(index.map((r) => r.agent).filter(Boolean))];
}

/** The notes that cite an evidence id. */
export function notesCiting(notes: readonly BundleNote[], id: string): BundleNote[] {
  return notes.filter((n) => n.evidence_ids.includes(id));
}
