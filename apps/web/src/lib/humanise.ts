/**
 * Machine names and machine values, as an analyst reads them.
 *
 * Two jobs, and they are the same job at two grains. A section the console has
 * no typed panel for is drawn from its own declared shape, which means its
 * column headers are whatever key the tool used — `optional_dependency`,
 * `technique_ids`, `sample_count` — sitting beside "Rule Category" and
 * "Capability" in the sibling table. And a header table's *values* arrive as
 * the constants the file format stores them as: `machine 34404`,
 * `subsystem 2`, `timestamp 1566949827`, `size 4486656`.
 *
 * Neither is a finding until it is read back into the words the reader knows.
 * Nothing here decides what to show — that stays with the tab — only how to
 * say it.
 */

import { formatBytes } from "./report-utils";

/** Words that are read as letters, so title-casing them would be wrong. */
const ACRONYMS = new Set([
  "api",
  "apk",
  "asn",
  "cpu",
  "dex",
  "dll",
  "dns",
  "elf",
  "fp",
  "ftp",
  "http",
  "https",
  "id",
  "ioc",
  "ip",
  "ja3",
  "ja3s",
  "md5",
  "mime",
  "os",
  "pe",
  "pid",
  "qa",
  "sha1",
  "sha256",
  "sha512",
  "ssdeep",
  "stix",
  "tlsh",
  "ttp",
  "url",
  "uuid",
  "yara",
]);

/** Whether a word is an acronym, its plural `s` aside: `ids` is IDs. */
function acronymOf(part: string): string | null {
  const lower = part.toLowerCase();
  if (ACRONYMS.has(lower)) return lower.toUpperCase();
  if (lower.endsWith("s") && ACRONYMS.has(lower.slice(0, -1))) {
    return `${lower.slice(0, -1).toUpperCase()}s`;
  }
  return null;
}

/** One word of a key, cased the way a reader writes it. */
function word(part: string): string {
  const lower = part.toLowerCase();
  return acronymOf(lower) ?? lower.charAt(0).toUpperCase() + lower.slice(1);
}

/**
 * A snake_case or dotted key as a heading.
 *
 * The first word carries the capital and the rest stay lowercase, which is
 * sentence case — the same shape as the hand-written headings it sits beside
 * ("Rule category", not "Rule Category") — except for the acronyms, which are
 * upper whatever position they are in.
 */
export function humaniseKey(key: string): string {
  const parts = (key ?? "").trim().split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 0) return "";
  return parts
    .map((part, i) => (i === 0 ? word(part) : (acronymOf(part) ?? part.toLowerCase())))
    .join(" ");
}

/* ── Values ─────────────────────────────────────────────────────────────── */

/** PE `IMAGE_FILE_HEADER.Machine`, as the values an analyst quotes. */
const PE_MACHINE: Record<string, string> = {
  "332": "x86",
  "34404": "x86-64",
  "452": "ARM",
  "43620": "ARM64",
  "448": "ARM Thumb-2",
  "512": "IA-64",
  "3772": "EFI byte code",
  "36929": "RISC-V 64",
};

/** PE `IMAGE_OPTIONAL_HEADER.Subsystem`. */
const PE_SUBSYSTEM: Record<string, string> = {
  "1": "Native",
  "2": "Windows GUI",
  "3": "Windows console",
  "5": "OS/2 console",
  "7": "POSIX console",
  "9": "Windows CE GUI",
  "10": "EFI application",
  "16": "Windows boot application",
};

/** Field names whose value is a byte count. */
const BYTE_FIELDS = new Set(["size", "file_size", "file_size_bytes", "size_of_image", "raw_size"]);
/** Field names whose value is a Unix timestamp. */
const EPOCH_FIELDS = new Set(["timestamp", "compile_timestamp", "timedatestamp", "compiled_at"]);
/** Field names conventionally quoted in hex. */
const HEX_FIELDS = new Set([
  "entry_point",
  "address_of_entry_point",
  "image_base",
  "base_of_code",
]);

function numeric(value: string): number | null {
  const text = value.trim();
  if (!/^\d+$/.test(text)) return null;
  const n = Number(text);
  return Number.isFinite(n) ? n : null;
}

/**
 * One header-table value, read back into what it means.
 *
 * Returns the value unchanged whenever the field is not one it knows or the
 * value is not the shape that field's constant takes — a tool that already
 * answered "x86-64" keeps saying so, and a machine id nothing here lists stays
 * the number rather than becoming a guess.
 */
export function humaniseValue(field: string, value: string): string {
  const key = (field ?? "").trim().toLowerCase().replace(/\s+/g, "_");
  const text = (value ?? "").trim();
  if (!text) return value;

  if (key === "machine") return PE_MACHINE[text] ?? text;
  if (key === "subsystem") return PE_SUBSYSTEM[text] ?? text;
  if (key === "file_type") return text.toUpperCase() === text ? text : humaniseFileType(text);

  const n = numeric(text);
  if (n === null) return text;
  if (BYTE_FIELDS.has(key)) return formatBytes(n);
  if (HEX_FIELDS.has(key)) return `0x${n.toString(16).padStart(8, "0")}`;
  if (EPOCH_FIELDS.has(key)) {
    // A PE timestamp is seconds since the epoch. Zero is the linker saying it
    // did not stamp one, and 1970 would be a fact the file does not carry.
    if (n === 0) return "not stamped";
    const at = new Date(n * 1000);
    // UTC, and it says so: a compile timestamp is quoted between analysts and
    // rendering it in the reader's own zone makes two people disagree about
    // the same file.
    if (Number.isNaN(at.getTime())) return text;
    return `${at.toISOString().replace("T", " ").slice(0, 19)} UTC`;
  }
  return text;
}

/** The routing label a run carries, as the format is written. */
function humaniseFileType(value: string): string {
  const known: Record<string, string> = {
    pe: "PE",
    elf: "ELF",
    "mach-o": "Mach-O",
    macho: "Mach-O",
    apk: "APK",
    dex: "DEX",
    jar: "JAR",
    pdf: "PDF",
  };
  return known[value.toLowerCase()] ?? value;
}

/** One key/value row, with both halves read back. */
export function humaniseRow(row: string[]): string[] {
  if (row.length < 2) return row;
  return [humaniseKey(row[0]), humaniseValue(row[0], row[1]), ...row.slice(2)];
}
