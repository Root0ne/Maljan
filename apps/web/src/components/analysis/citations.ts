/**
 * A citation as a reader follows it: the ledger ids in it, and the words
 * between them.
 *
 * An analyst's `evidence_ref` is prose more often than an id — "ev_0024 (row
 * 0x3868), ev_0019." or "ev_0138 (packed flag, ...); ev_0134 (...); ev_0004."
 * — and it was handed to the chips whole, so the whole sentence became one
 * `?evidence=` link that opened nothing. Here it is split: each id is its own
 * part, and what sits around the ids stays words.
 */

/** One ledger id: `ev_` and its number. */
const EVIDENCE_ID = /\bev_\d+\b/g;

export type CitationPart = { kind: "id"; id: string } | { kind: "text"; text: string };

/** Whether a string is one ledger id and nothing else. */
export function isEvidenceId(value: string): boolean {
  return /^ev_\d+$/.test(value.trim());
}

export interface CitedRecord {
  id: string;
  /** What the citation says of this record, its brackets and separators
   *  dropped; empty when it says nothing beyond the id. */
  label: string;
}

/**
 * A citation read as the records it names, each with the words written
 * after it: "[ev_0001] pe windows, 60,928 bytes. [ev_0003] dll" reads as
 * ev_0001 "pe windows, 60,928 bytes" and ev_0003 "dll". Words before the
 * first id are returned apart, as `lead`; a citation with no id at all is
 * all lead.
 */
export function citedRecords(text: string): { lead: string; records: CitedRecord[] } {
  const parts = citationParts(text ?? "");
  const clean = (s: string) =>
    s
      .replace(/[[\]()]/g, " ")
      .replace(/\s+/g, " ")
      .replace(/^[\s,;:.–—-]+|[\s,;:–—-]+$/g, "")
      .replace(/\.$/, "")
      .trim();
  let lead = "";
  const records: CitedRecord[] = [];
  for (const part of parts) {
    if (part.kind === "id") records.push({ id: part.id, label: "" });
    else if (records.length === 0) lead += part.text;
    else records[records.length - 1].label += part.text;
  }
  return { lead: clean(lead), records: records.map((r) => ({ id: r.id, label: clean(r.label) })) };
}

/** The ids and the prose of one citation, in the order they were written. */
export function citationParts(text: string): CitationPart[] {
  const parts: CitationPart[] = [];
  let last = 0;
  for (const match of text.matchAll(EVIDENCE_ID)) {
    const at = match.index ?? 0;
    if (at > last) parts.push({ kind: "text", text: text.slice(last, at) });
    parts.push({ kind: "id", id: match[0] });
    last = at + match[0].length;
  }
  if (last < text.length) parts.push({ kind: "text", text: text.slice(last) });
  return parts;
}
