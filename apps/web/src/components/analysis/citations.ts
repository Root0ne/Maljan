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
