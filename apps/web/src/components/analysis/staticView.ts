/**
 * How the Static & code tab sorts what reading the file showed.
 *
 * The sections a tool wrote are placed by their shape, never by the tool:
 * the four tables a format tool contributes go to the file-structure
 * sub-tab their key's suffix names (`_sections`, `_imports`, `_exports`),
 * the printable strings to the strings block, the functions examined — and
 * any section whose cells are listings of several lines, which is what a
 * decompiler's excerpt is — to the functions block, and the rest to "other
 * findings". The strings the static pass classified are filtered by kind and
 * by a search over their value and notes.
 */

import type { EvidenceSection, StringIOC, StringIOCKind } from "@/types/malware-report";

/** How many rows each static table draws before offering more. */
export const STATIC_ROWS_STEP = 10;

export type StructureTab = "sections" | "imports" | "exports" | "resources";

export const STRUCTURE_TABS: { key: StructureTab; label: string }[] = [
  { key: "sections", label: "Sections" },
  { key: "imports", label: "Imports" },
  { key: "exports", label: "Exports" },
  { key: "resources", label: "Resources" },
];

/* Ordered by what an analyst reaches for first, not alphabetically. `secret`
 * and `crypto_wallet` sit high because a leaked credential is the one finding
 * that changes what someone does in the next five minutes. */
export const STRING_KIND_ORDER: StringIOCKind[] = [
  "secret",
  "crypto_wallet",
  "url",
  "domain",
  "ip",
  "registry",
  "path",
  "mutex",
  "email",
  "command",
  "other",
];

/** A cell of several lines: a listing, a decompiled function. */
function isListing(section: EvidenceSection): boolean {
  return (section.rows ?? []).some((row) => row.some((cell) => typeof cell === "string" && cell.includes("\n")));
}

export interface StaticSlots {
  structure: Record<Exclude<StructureTab, "resources">, EvidenceSection[]>;
  strings: EvidenceSection[];
  functions: EvidenceSection[];
  other: EvidenceSection[];
}

/** The static tab's sections, each in the one place it is drawn. */
export function staticSlots(sections: readonly EvidenceSection[]): StaticSlots {
  const slots: StaticSlots = { structure: { sections: [], imports: [], exports: [] }, strings: [], functions: [], other: [] };
  for (const section of sections) {
    const key = section.key.trim();
    if (key.endsWith("_sections")) slots.structure.sections.push(section);
    else if (key.endsWith("_imports")) slots.structure.imports.push(section);
    else if (key.endsWith("_exports")) slots.structure.exports.push(section);
    else if (key === "strings") slots.strings.push(section);
    else if (key === "functions_examined" || isListing(section)) slots.functions.push(section);
    else slots.other.push(section);
  }
  return slots;
}

/** The kinds present among the strings, in reading order, with their counts. */
export function stringFacets(strings: readonly StringIOC[]): { kind: StringIOCKind; count: number }[] {
  const counts = new Map<StringIOCKind, number>();
  for (const s of strings) counts.set(s.kind, (counts.get(s.kind) ?? 0) + 1);
  const known = STRING_KIND_ORDER.filter((k) => counts.has(k));
  const rest = [...counts.keys()].filter((k) => !STRING_KIND_ORDER.includes(k));
  return [...known, ...rest].map((kind) => ({ kind, count: counts.get(kind) ?? 0 }));
}

/** The strings one kind and one search keep. */
export function filterStrings(
  strings: readonly StringIOC[],
  kind: StringIOCKind | "all",
  query: string,
): StringIOC[] {
  const q = query.trim().toLowerCase();
  return strings.filter(
    (s) =>
      (kind === "all" || s.kind === kind) &&
      (!q || s.value.toLowerCase().includes(q) || (s.notes ?? "").toLowerCase().includes(q)),
  );
}
