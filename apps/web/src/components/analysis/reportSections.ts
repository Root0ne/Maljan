/**
 * Which tab each report section belongs on, and which typed panel it replaces.
 *
 * `report.sections` is the open half of the report: one entry per shape the
 * tools actually produced, including shapes nothing in this codebase models.
 * The typed panels are the closed half — the PE section table, the process
 * tree, the network IOC lists — written when the only sample anyone expected
 * was a Windows executable.
 *
 * Both halves render, and the rule between them is simple: a section is the
 * primary content, and a typed panel draws only when it has data of its own
 * *and* no section already covers the same ground. Two tables of the same
 * imports, one from the ledger and one from the extractor, is not two findings.
 *
 * Section keys are named after what produced them (`pe_imports`,
 * `sandbox_registry`, `tool_<name>`), so the routing is a map rather than a
 * prefix test. A dotted key (`static.imports`) is understood too: if the
 * report ever carries the tab in the key, this needs no change, and until then
 * nothing has to be renamed for the console to work.
 */

import type { EvidenceSection } from "@/types/malware-report";

export type SectionTab =
  | "identity"
  | "static"
  | "dynamic"
  | "network"
  | "persistence"
  | "detection"
  | "other";

/**
 * The tabs that actually draw their sections, and the only list that decides.
 *
 * A tab in this set has a page that calls `sectionsForTab` and renders the
 * result; a key routed to a tab that is not in it would be built, persisted,
 * counted in the evidence metrics and drawn nowhere. `unrenderedSections`
 * below is the net that catches exactly that, so adding a tab to `SectionTab`
 * without giving it a renderer costs a section its page but never loses it.
 */
export const RENDERED_TABS: ReadonlySet<SectionTab> = new Set<SectionTab>([
  "identity",
  "static",
  "dynamic",
  "network",
  "persistence",
  // DETECTION draws its two sections as rule rows (`ruleMatches.ts`) rather
  // than through `sectionsForTab`, and draws both whenever they have content.
  "detection",
]);

/** The heads a dotted key may carry, which is every tab but the fallback. */
const TABS = new Set<string>([
  "identity",
  "static",
  "dynamic",
  "network",
  "persistence",
  "detection",
]);

/** The keys whose tab is not derivable from their shape. */
const BY_KEY: Record<string, SectionTab> = {
  identity: "identity",
  strings: "static",
  // The rules that fired are DETECTION's, with each Sigma rule's own level on
  // the severity ladder; STATIC links there rather than repeating the table.
  yara_matches: "detection",
  sigma_matches: "detection",
  capa_capabilities: "static",
  functions_examined: "static",
  packer_signatures: "static",
  apk_permissions: "static",
  apk_components: "static",
  iocs: "network",
  pcap_summary: "network",
  sandbox_network: "network",
  // Registry writes sit beside the typed panel they may replace, which is on
  // the behaviour tab. A service or a scheduled task is a persistence
  // mechanism whatever observed it, and the persistence tab has nothing else
  // from the ledger.
  sandbox_registry: "dynamic",
  sandbox_services_and_tasks: "persistence",
  artifact_persistence: "persistence",
};

/** The four tables a binary-info tool contributes, and where each belongs. */
const BY_SUFFIX: Array<[string, SectionTab]> = [
  ["_header", "identity"],
  ["_sections", "static"],
  ["_imports", "static"],
  ["_exports", "static"],
];

/** The tab a section is drawn on. */
export function tabOfSection(key: string): SectionTab {
  const name = (key ?? "").trim();
  if (!name) return "other";
  const dot = name.indexOf(".");
  if (dot > 0) {
    const head = name.slice(0, dot);
    if (TABS.has(head)) return head as SectionTab;
  }
  const known = BY_KEY[name];
  if (known) return known;
  for (const [suffix, tab] of BY_SUFFIX) if (name.endsWith(suffix)) return tab;
  // Everything the sandbox reported that is not registry, services or network
  // is behaviour, which is what the DYNAMIC tab is.
  if (name.startsWith("sandbox_")) return "dynamic";
  return "other";
}

/**
 * Whether one cell says anything.
 *
 * A key/value row whose value is empty, or the `-` a table prints for empty,
 * is a field the tool has rather than a fact about the sample.
 */
export function saysSomething(value: string | null | undefined): boolean {
  const text = (value ?? "").trim();
  return text !== "" && text !== "-";
}

/** A section carries something worth drawing. */
export function sectionHasContent(section: EvidenceSection): boolean {
  return Boolean(
    (section.rows?.length ?? 0) > 0 ||
      (section.items?.length ?? 0) > 0 ||
      (section.text ?? "").trim()
  );
}

/** The sections one tab draws, in the order the run gathered them. */
export function sectionsForTab(
  sections: EvidenceSection[] | null | undefined,
  tab: SectionTab
): EvidenceSection[] {
  return (sections ?? []).filter(
    (section) => sectionHasContent(section) && tabOfSection(section.key) === tab
  );
}

/**
 * Whether a section already covers the ground a typed panel would.
 *
 * The caller names the section keys its panel duplicates, because only the
 * panel knows what it is a table of. A key that is not present, or present and
 * empty, covers nothing — an empty section is a tool that ran and returned
 * nothing, which is not a reason to hide the extractor's answer.
 */
export function isCoveredBySection(
  sections: EvidenceSection[] | null | undefined,
  keys: string[]
): boolean {
  const wanted = new Set(keys);
  return (sections ?? []).some(
    (section) => wanted.has(section.key) && sectionHasContent(section)
  );
}

/**
 * Every section whose tab does not draw it, plus the ones no tab claims.
 *
 * The EVIDENCE tab shows these beside the calls they were built from. It is a
 * net rather than a list: a section is lost only if it is routed to a tab that
 * renders sections and that tab then fails to draw it, which is a bug in one
 * page rather than a hole in the routing. Everything else lands here.
 */
export function unrenderedSections(
  sections: EvidenceSection[] | null | undefined
): EvidenceSection[] {
  return (sections ?? []).filter(
    (section) =>
      sectionHasContent(section) && !RENDERED_TABS.has(tabOfSection(section.key))
  );
}

/** Whether one named section is present with content. */
export function hasSection(
  sections: EvidenceSection[] | null | undefined,
  key: string
): boolean {
  return isCoveredBySection(sections, [key]);
}

/**
 * The noun a format uses for the thing an import comes out of.
 *
 * The imports table said "Module" for every sample, which is a Windows word
 * wearing a neutral coat: an ELF imports from a shared object and an APK from
 * a package, and calling either a module is the kind of small lie that makes a
 * reader distrust the rest of the page.
 */
export function importContainerLabel(fileType: string | null | undefined): string {
  switch ((fileType ?? "").toLowerCase()) {
    case "pe":
      return "DLL";
    case "elf":
      return "Shared object";
    case "mach-o":
      return "Dylib";
    case "apk":
    case "dex":
      return "Package";
    case "jar":
      return "Package";
    default:
      return "Module";
  }
}

/** The formats whose info tool contributes header/sections/imports/exports. */
const BINARY_PREFIXES = ["pe", "elf", "macho", "apk"];

/**
 * The section keys a binary-info tool would have used for one of its tables.
 *
 * A typed panel does not know which format produced the run, and asking it to
 * would put the format list in four places. It names the table it draws and
 * gets every key that could hold the same table.
 */
export function binarySectionKeys(suffix: "header" | "sections" | "imports" | "exports") {
  return BINARY_PREFIXES.map((prefix) => `${prefix}_${suffix}`);
}
