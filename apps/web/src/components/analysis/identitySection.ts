/**
 * The identity section, read for the two things it holds that have a home of
 * their own on the tab.
 *
 * `identity` is one key/value section built from three tools — `identify_file`,
 * `hashes` and `signing_info` — plus the two routing facts. Two of those tools
 * put rows in it that the IDENTITY tab already draws better:
 *
 * * the hashes, which belong in the File hashes block with the copy buttons a
 *   reader actually uses, and were otherwise printed twice on one screen;
 * * the signing answer, which reads as `present=no` rather than as a
 *   sentence.
 *
 * So the section is split here: the hashes come out and go to the block that
 * holds them, the signing row becomes a sentence, and every row left whose
 * value says nothing is dropped.
 *
 * `signing_info` now answers for the routed format alone, so a report carries
 * one signing row. Choosing between three of them is kept for the reports
 * written before it did, where a PE also carried "apk present=no" and "macho
 * present=no" — facts about what the tool looks for, which this drops rather
 * than draw as findings about the sample.
 */

import { humaniseKey, humaniseValue } from "@/lib/humanise";
import { saysSomething } from "./reportSections";
import type { EvidenceSection } from "@/types/malware-report";

/** Hash names the File hashes block draws, in the order it draws them. */
export const HASH_FIELDS = [
  "md5",
  "sha1",
  "sha256",
  "sha512",
  "imphash",
  "ssdeep",
  "tlsh",
  "telfhash",
] as const;
export type HashField = (typeof HASH_FIELDS)[number];

const HASH_FIELD_SET: ReadonlySet<string> = new Set<string>(HASH_FIELDS);

/**
 * The signing block each routed format answers under, and its heading.
 *
 * Matched loosely on purpose: `file_type` is the lowercase routing label
 * (`pe`, `apk`, `mach-o`) on a report the extractor wrote, and whatever
 * `identify_file` called the format (`PE32 executable`) on one it did not.
 * The heading is what a current report's single row is titled with; the
 * matching itself only ever has to choose on an older one.
 */
const SIGNING_BLOCKS: { matches: RegExp; field: string; label: string }[] = [
  { matches: /^pe\b|^pe32/, field: "authenticode", label: "Authenticode" },
  { matches: /^(apk|dex|jar)/, field: "apk", label: "APK signing" },
  { matches: /mach-?o/, field: "macho", label: "Mach-O signature" },
];

function signingBlockFor(fileType: string | null | undefined) {
  const text = (fileType ?? "").trim().toLowerCase();
  if (!text) return undefined;
  return SIGNING_BLOCKS.find((block) => block.matches.test(text));
}

const SIGNING_FIELDS: ReadonlySet<string> = new Set(["authenticode", "apk", "macho"]);

/**
 * Rows `signing_info` carries that are about the tool rather than the sample.
 *
 * `format` repeats the routing answer `identify_file` already states two rows
 * above, and `applicable` says this format has no code-signing scheme to look
 * for — which is not a finding about the sample, and is exactly the kind of
 * row the signing block was split out to stop drawing. The exported report
 * leaves both out; this is the reader's side of the same rule, for a report
 * stored while the two were still being written.
 */
const TOOL_FIELDS: ReadonlySet<string> = new Set(["format", "applicable"]);

/** The `k=v, k=v` prose a dict value is flattened into, back as pairs. */
function pairsOf(value: string): Map<string, string> {
  const pairs = new Map<string, string>();
  for (const part of value.split(",")) {
    const at = part.indexOf("=");
    if (at < 0) continue;
    pairs.set(part.slice(0, at).trim(), part.slice(at + 1).trim());
  }
  return pairs;
}

/**
 * One signing block as a sentence.
 *
 * `null` when the block says nothing at all, which is what a format the tool
 * never looked at leaves behind.
 */
export function signingSentence(value: string): string | null {
  const pairs = pairsOf(value);
  const present = pairs.get("present");
  if (present === undefined) return saysSomething(value) ? value : null;
  if (present !== "yes") return "Not signed";

  /* Presence, never validity: verifying a chain needs a trust store the tool
   * does not have, and `signing_info` says so itself. The signer and the
   * issuer are the Code signing block's, so the row states the one fact it is
   * the row for. */
  return "Carries a signature";
}

export interface IdentityView {
  /** The section as the tab should draw it, or `null` when nothing is left. */
  section: EvidenceSection | null;
  /** Every hash the ledger reported, keyed by its field name. */
  hashes: Partial<Record<HashField, string>>;
  /** Whether the table now states whether the sample is signed, so the typed
   *  block's own badge can stand down rather than say it a second time. */
  signing: boolean;
  /** The typed block's own field labels this table already carries, so that
   *  block can drop them rather than print the same fact beside it. `size`
   *  used to appear in both tables on one screen, once as `4486656` and once
   *  as "4.3 MB". */
  states: ReadonlySet<string>;
}

/** The ledger field each typed identity field restates. */
const TYPED_FIELD_OF: Record<string, string> = {
  file_name: "File Name",
  file_type: "File Type",
  size: "Size",
  file_size: "Size",
  mime_type: "MIME Type",
  timestamp: "Compile Timestamp",
  compile_timestamp: "Compile Timestamp",
};

/**
 * Split the identity section into the table and the hashes.
 *
 * `fileType` is the format the run routed on. A current report carries one
 * signing block, the one the pack asked about; on a report written before
 * that, `fileType` is what decides which of the three is about this sample,
 * and a format nothing here knows keeps any block that reports a signature
 * and drops the ones that report none — a "no" about a format the sample is
 * not is not a finding.
 */
export function readIdentitySection(
  section: EvidenceSection | null | undefined,
  fileType: string | null | undefined,
): IdentityView {
  const hashes: Partial<Record<HashField, string>> = {};
  const states = new Set<string>();
  if (!section) return { section: null, hashes, signing: false, states };

  const routed = signingBlockFor(fileType);
  const rows: string[][] = [];
  let signing = false;

  for (const row of section.rows ?? []) {
    const field = (row[0] ?? "").trim();
    const value = row[1] ?? "";

    if (HASH_FIELD_SET.has(field)) {
      if (saysSomething(value)) hashes[field as HashField] = value.trim();
      continue;
    }

    if (TOOL_FIELDS.has(field)) continue;

    if (SIGNING_FIELDS.has(field)) {
      const applies = routed ? field === routed.field : pairsOf(value).get("present") === "yes";
      if (!applies) continue;
      const sentence = signingSentence(value);
      if (!sentence) continue;
      signing = true;
      rows.push([routed?.label ?? `${humaniseKey(field)} signature`, sentence]);
      continue;
    }

    if (!saysSomething(value)) continue;
    const typed = TYPED_FIELD_OF[field.toLowerCase().replace(/\s+/g, "_")];
    if (typed) states.add(typed);
    // A file format's own constants — `machine 34404`, `subsystem 2`, an
    // epoch, a byte count — are facts about the sample only once they are read
    // back into the words an analyst quotes.
    rows.push([humaniseKey(field), humaniseValue(field, value)]);
  }

  if (rows.length === 0) return { section: null, hashes, signing, states };
  return { section: { ...section, rows }, hashes, signing, states };
}
