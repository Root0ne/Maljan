/**
 * The rules the evidence panel runs on, kept out of the component.
 *
 * The panel itself is a table, a few selects and a fetch. What is worth
 * testing is everything around them — which page an `ev_0007` deep link lands
 * on, what a filter change does to the page number, how an argument object is
 * shortened to fit a cell — and those are plain functions over plain data, the
 * same split `pipelineSteps.ts` uses.
 */

import type { EvidenceEntry, EvidenceQuery } from "@/types/evidence";

/** One page of the ledger. Large enough that most runs fit on one or two. */
export const EVIDENCE_PAGE_SIZE = 50;

/** How much of an argument object a collapsed row shows. */
export const ARGS_SUMMARY_CHARS = 80;

/** The three grains the ledger can be narrowed to. Empty means no filter. */
export interface EvidenceFilters {
  stage: string;
  agent: string;
  tool: string;
}

export const NO_FILTERS: EvidenceFilters = { stage: "", agent: "", tool: "" };

/**
 * The query one page under one set of filters is fetched with.
 *
 * Filtering happens on the server rather than over the page already fetched,
 * because a filter over one page of fifty answers a different question from
 * the one the operator asked: "the calls this agent made" is not "the calls
 * this agent made that happen to be on the page I am looking at".
 */
export function evidenceQuery(filters: EvidenceFilters, page: number): EvidenceQuery {
  const query: EvidenceQuery = { page: Math.max(1, page), pageSize: EVIDENCE_PAGE_SIZE };
  if (filters.stage) query.stage = filters.stage;
  if (filters.agent) query.agent = filters.agent;
  if (filters.tool) query.tool = filters.tool;
  return query;
}

/** How many pages `total` entries fill. Always at least one, so the footer
 *  reads "1 of 1" on an empty ledger rather than "1 of 0". */
export function pageCount(total: number, pageSize = EVIDENCE_PAGE_SIZE): number {
  return Math.max(1, Math.ceil(Math.max(0, total) / pageSize));
}

/**
 * The page a citation lands on, or `null` when the id is not one of ours.
 *
 * Entry ids are `ev_` and the call's sequence number across the whole run,
 * one-based and zero-padded, so the page a citation is on is arithmetic rather
 * than a search. It is derived from the id instead of asked for because a deep
 * link has to work on the first render, before any page has been fetched.
 */
export function pageOfEntry(entryId: string, pageSize = EVIDENCE_PAGE_SIZE): number | null {
  const match = /^ev_(\d+)$/.exec((entryId ?? "").trim());
  if (!match) return null;
  const seq = Number(match[1]);
  if (!Number.isFinite(seq) || seq < 1) return null;
  return Math.floor((seq - 1) / pageSize) + 1;
}

/**
 * A deep link overrides the filters rather than being applied under them.
 *
 * An operator following `ev_0007` from a report section wants that entry, and
 * a filter left over from whatever they were doing before would hide it and
 * say the ledger was empty.
 */
export function deepLinkView(
  entryId: string,
  pageSize = EVIDENCE_PAGE_SIZE
): { filters: EvidenceFilters; page: number } | null {
  const page = pageOfEntry(entryId, pageSize);
  if (page === null) return null;
  return { filters: { ...NO_FILTERS }, page };
}

/** Setting a filter goes back to page one: page four of the unfiltered ledger
 *  is rarely page four of the filtered one, and often past its end. */
export function withFilter(
  filters: EvidenceFilters,
  field: keyof EvidenceFilters,
  value: string
): { filters: EvidenceFilters; page: number } {
  return { filters: { ...filters, [field]: value }, page: 1 };
}

/** One argument object, shortened to fit a cell. */
export function argsSummary(
  args: Record<string, unknown> | null | undefined,
  limit = ARGS_SUMMARY_CHARS
): { text: string; truncated: boolean } {
  if (!args || Object.keys(args).length === 0) return { text: "", truncated: false };
  let full: string;
  try {
    full = JSON.stringify(args);
  } catch {
    // A tool that handed back something JSON cannot describe still gets a row.
    full = String(args);
  }
  if (full.length <= limit) return { text: full, truncated: false };
  return { text: `${full.slice(0, limit)}…`, truncated: true };
}

/** The full argument object, indented, for an expanded row. */
export function argsDetail(args: Record<string, unknown> | null | undefined): string {
  if (!args) return "";
  try {
    return JSON.stringify(args, null, 2);
  } catch {
    return String(args);
  }
}

/**
 * The values each filter offers, accumulated across the pages seen so far.
 *
 * The endpoint serves one page, so the only stages, agents and tools this
 * knows about are the ones that have come back. Accumulating rather than
 * replacing keeps an option from disappearing the moment it is chosen — a
 * filtered page contains only its own value, and rebuilding the list from it
 * would leave a select with one option and no way back.
 */
export function mergeOptions(
  seen: Record<keyof EvidenceFilters, string[]>,
  entries: EvidenceEntry[]
): Record<keyof EvidenceFilters, string[]> {
  const add = (field: keyof EvidenceFilters, values: (string | null)[]) => {
    const merged = new Set(seen[field] ?? []);
    for (const value of values) if (value) merged.add(value);
    return [...merged].sort();
  };
  return {
    stage: add("stage", entries.map((e) => e.stage)),
    agent: add("agent", entries.map((e) => e.agent)),
    tool: add("tool", entries.map((e) => e.tool)),
  };
}

export const EMPTY_OPTIONS: Record<keyof EvidenceFilters, string[]> = {
  stage: [],
  agent: [],
  tool: [],
};

/** How much of a tool's output an unexpanded disclosure shows. */
export const OUTPUT_PREVIEW_CHARS = 2_000;

/** A tool output, and whether the reader is being shown all of it. */
export function outputPreview(
  output: string,
  expanded: boolean,
  limit = OUTPUT_PREVIEW_CHARS
): { text: string; hidden: number } {
  const body = output ?? "";
  if (expanded || body.length <= limit) return { text: body, hidden: 0 };
  return { text: body.slice(0, limit), hidden: body.length - limit };
}

/** A duration in the units a reader of a tool call thinks in. */
export function formatCallDuration(ms: number): string {
  const value = Number(ms) || 0;
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}
