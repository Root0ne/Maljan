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

/**
 * What to say about an output that is empty, when anything is known.
 *
 * An empty output has more than one cause, and only the entry itself can tell
 * them apart. A call trimmed to keep its agent inside its byte budget says so
 * with `truncated`; a call that failed carries `error` and is drawn as a
 * failure in its own right; a call that simply answered with nothing is
 * neither. Reading the emptiness as a trim — which is what this view did
 * before the flag was persisted — printed the budget sentence under a failure
 * row, stating a cause that had not happened.
 *
 * A row from before the column exists carries no flag, so it falls to the
 * neutral sentence: what is not recorded is not asserted.
 */
export function emptyOutputNote(entry: EvidenceEntry): string {
  if (entry.truncated) {
    return (
      "The output was dropped to keep this agent inside its byte budget. " +
      "The call, its arguments and its outcome stand."
    );
  }
  return "This call recorded no output.";
}

/** A duration in the units a reader of a tool call thinks in. */
export function formatCallDuration(ms: number): string {
  const value = Number(ms) || 0;
  if (value < 1000) return `${value} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

/** The extension a saved spilled part is named with, from its content type. */
const EXTENSIONS: Record<string, string> = {
  "application/json": "json",
  "application/x-ndjson": "ndjson",
  "application/xml": "xml",
  "application/pdf": "pdf",
  "application/zip": "zip",
  "application/gzip": "gz",
  "application/octet-stream": "bin",
  "text/plain": "txt",
  "text/csv": "csv",
  "text/html": "html",
  "text/xml": "xml",
};

/** `ev_0007-structured_content.json`: the entry, the part and the type's extension. */
export function spilledFileName(entryId: string, part: string, contentType: string): string {
  const type = contentType.split(";")[0].trim().toLowerCase();
  const ext =
    EXTENSIONS[type] ??
    (type.endsWith("+json") ? "json" : type.startsWith("text/") ? "txt" : "bin");
  return `${entryId}-${part}.${ext}`;
}

function hex(buffer: ArrayBuffer): string {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Why a fetched spilled part must not be saved, or `null` when it may.
 *
 * The ledger records each kept part's size and SHA-256. A body shorter than
 * the response or the ledger says, or one whose digest differs, is not the
 * part the run kept, and saving it would hand the reader a file that reads as
 * evidence and is not.
 */
export interface SpilledCheck {
  /** Why the part must not be saved; `null` when it may. */
  problem: string | null;
  /** Set when the digest could not be checked, said beside the saved file. */
  unverified: string | null;
}

/** The browser's digest, absent outside a secure context (plain http off localhost). */
type Subtle = Pick<SubtleCrypto, "digest"> | undefined;

function browserSubtle(): Subtle {
  return globalThis.crypto?.subtle;
}

export async function spilledProblem(
  bytes: ArrayBuffer,
  ref: { bytes?: number; sha256?: string },
  declaredLength: number | null,
  subtle: Subtle | null = browserSubtle() ?? null,
): Promise<SpilledCheck> {
  const got = bytes.byteLength;
  if (declaredLength !== null && got !== declaredLength) {
    return {
      problem: `The download was cut short (${got} of ${declaredLength} bytes); nothing was saved.`,
      unverified: null,
    };
  }
  if (typeof ref.bytes === "number" && got !== ref.bytes) {
    return {
      problem: `The download is ${got} bytes but the ledger kept ${ref.bytes}; nothing was saved.`,
      unverified: null,
    };
  }
  if (ref.sha256) {
    /* `crypto.subtle` exists only in a secure context, so a console served
     * over plain http on a LAN address has no digest to check with. The
     * length was checked above; the file is saved and the reader told the
     * digest was not. */
    if (!subtle) {
      return {
        problem: null,
        unverified: "Saved; its digest was not checked (this page is not a secure context).",
      };
    }
    const digest = hex(await subtle.digest("SHA-256", bytes));
    if (digest !== ref.sha256.toLowerCase()) {
      return {
        problem: "The download does not match the digest the ledger recorded; nothing was saved.",
        unverified: null,
      };
    }
  }
  return { problem: null, unverified: null };
}

/**
 * What the ledger recorded about how this call's answer was kept, said where
 * the row is drawn.
 *
 * Four facts an entry can carry were stored and never shown: that the answer
 * the model read was cut (`truncated`, `chars_dropped`), that parts of it are
 * kept whole elsewhere (`spilled`), that the call was answered from an earlier
 * identical one (`repeated_of`), and that the model's arguments arrived cut
 * off and were closed before the call ran (`args_repaired`). A reader of the
 * row saw a whole answer, a fresh call and the model's own arguments in all
 * four cases. The nulls a call left out (`args_nulls_dropped`,
 * `args_nulls_withheld`) are said the same way. Each is a sentence here; a row that carries none of them says
 * nothing, because what is not recorded is not asserted.
 */
export function entryNotes(entry: EvidenceEntry): string[] {
  const notes: string[] = [];
  const dropped = Number(entry.chars_dropped) || 0;
  if (dropped > 0) {
    notes.push(
      `The tool-output guardrail cut ${dropped.toLocaleString("en-US")} characters from the answer the model read.`,
    );
  } else if (entry.truncated && entry.output) {
    notes.push("The answer the model read was shortened to keep this agent inside its byte budget.");
  }
  for (const ref of entry.spilled ?? []) {
    const part = ref.part.replace(/_/g, " ");
    if (ref.key) {
      const size =
        typeof ref.bytes === "number" ? ` (${ref.bytes.toLocaleString("en-US")} bytes)` : "";
      notes.push(`The full ${part}${size} is kept whole in object storage.`);
    } else {
      notes.push(`The full ${part} could not be kept${ref.error ? `: ${ref.error}` : "."}`);
    }
  }
  if (entry.repeated_of) {
    notes.push(`Answered from the earlier identical call ${entry.repeated_of}, not run again.`);
  }
  if (entry.args_repaired) {
    notes.push("The model's arguments arrived cut off and were closed before the call ran.");
  }
  const named = (paths: string[][] | null | undefined): string =>
    (paths ?? []).map((path) => path.join(" › ")).join(", ");
  const nullsDropped = named(entry.args_nulls_dropped);
  if (nullsDropped) {
    notes.push(
      `The model gave null for ${nullsDropped}, which the tool's schema does not allow; each was left out and took its default.`,
    );
  }
  const nullsWithheld = named(entry.args_nulls_withheld);
  if (nullsWithheld) {
    notes.push(
      `The model gave null for ${nullsWithheld}; it was not sent, so the server applied its own default.`,
    );
  }
  return notes;
}
