"use client";

import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import { useMemo, useState } from "react";
import Link from "next/link";

import CopyButton from "@/components/ui/CopyButton";
import Section from "@/components/ui/Section";
import ShowMoreRows from "@/components/ui/ShowMoreRows";
import Th from "@/components/ui/Th";
import VerticalTabs from "@/components/ui/VerticalTabs";
import { entropyClass, formatBytes } from "@/lib/report-utils";
import { ArtifactSections } from "@/components/analysis/ArtifactTable";
import CallMap from "@/components/analysis/CallMap";
import EvidenceChips from "@/components/analysis/EvidenceChips";
import {
  binarySectionKeys,
  importContainerLabel,
  hasSection,
  isCoveredBySection,
  sectionsForTab,
} from "@/components/analysis/reportSections";
import { SIGMA_SECTION, YARA_SECTION } from "@/components/analysis/ruleMatches";
import {
  STATIC_ROWS_STEP,
  STRUCTURE_TABS,
  filterStrings,
  staticSlots,
  stringFacets,
  type StructureTab,
} from "@/components/analysis/staticView";
import { configFindings } from "@/components/analysis/reportProse";
import { fileTypeLabel } from "@/types/malware-report";
import type { ReportDetailDTO } from "@/lib/api";
import type { StringIOCKind } from "@/types/malware-report";

/**
 * What reading the file without running it showed: its structure (sections,
 * imports, exports and resources, one at a time), the strings it carries,
 * the configuration recovered from it, the functions the analysis examined
 * and the map of what they call. The sections a tool wrote lead each place;
 * the extractor's typed table draws where no section says the same thing.
 */
export default function StaticContent({ report }: { report: ReportDetailDTO }) {
  const [tab, setTab] = useState<StructureTab>("sections");
  const [stringKind, setStringKind] = useState<StringIOCKind | "all">("all");
  const [query, setQuery] = useState("");
  /* How many rows each table draws; every row stays reachable. */
  const [shown, setShown] = useState<Record<string, number>>({});
  const shownOf = (t: string) => shown[t] ?? STATIC_ROWS_STEP;
  const show = (t: string) => (n: number) => setShown((s) => ({ ...s, [t]: n }));

  const mr = report.malware_report;
  const staticData = mr?.static ?? null;
  const fileType = mr?.identity?.file_type;
  const reportSections = mr?.sections;
  const slots = staticSlots(sectionsForTab(reportSections, "static", report.section_tabs));
  /* The YARA and Sigma rules that fired are on Indicators & detection, where
   * each Sigma rule's level sits on the severity ladder. This page points
   * there rather than drawing the same table a second time. */
  const rulesFired = hasSection(reportSections, YARA_SECTION) || hasSection(reportSections, SIGMA_SECTION);
  const showsExtractedSections = !isCoveredBySection(reportSections, binarySectionKeys("sections"));
  const showsImports = !isCoveredBySection(reportSections, binarySectionKeys("imports"));
  const showsExports = !isCoveredBySection(reportSections, binarySectionKeys("exports"));
  const importContainer = importContainerLabel(fileType);

  const strings = useMemo(() => staticData?.interesting_strings ?? [], [staticData]);
  const filteredStrings = useMemo(() => filterStrings(strings, stringKind, query), [strings, stringKind, query]);
  const facets = useMemo(() => stringFacets(strings), [strings]);
  const resources = staticData?.embedded_resources ?? [];
  const carved = resources.filter((r) => r.carved);
  const techniqueHits = useMemo(
    () => [...(staticData?.api_technique_hits ?? [])].sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0)),
    [staticData],
  );
  // A row is a rule, and two rules can name one technique by two mechanisms —
  // so the heading counts techniques and the table draws the rule that tells
  // the two rows apart.
  const techniqueCount = new Set(techniqueHits.map((h) => h.technique_id ?? "")).size;
  const capabilityProfile = Object.entries(staticData?.api_capabilities ?? {}).sort((a, b) => b[1] - a[1]);
  const exportRows = staticData?.export_rows ?? [];
  const exportTotal = exportRows.length || (staticData?.exports.length ?? 0);
  const config = mr?.technical_analysis?.configuration ?? [];
  const uncitedConfig = configFindings(mr);

  const typedCount: Record<StructureTab, number> = {
    sections: showsExtractedSections ? (staticData?.sections.length ?? 0) : 0,
    imports: showsImports ? (staticData?.imports.length ?? 0) : 0,
    exports: showsExports ? exportTotal : 0,
    resources: resources.length,
  };
  const sectionRows = (t: StructureTab) =>
    t === "resources" ? 0 : slots.structure[t].reduce((n, s) => n + (s.rows?.length || s.items?.length || 0), 0);
  const tabCount = (t: StructureTab) => typedCount[t] + sectionRows(t);
  const structureEmpty = STRUCTURE_TABS.every((t) => tabCount(t.key) === 0) && techniqueHits.length === 0;
  const structureTitle = fileType ? `${fileTypeLabel(fileType)} details` : "File structure";

  return (
    <div className="space-y-4">
      {rulesFired && report.job_id && (
        <p className="text-xs text-text-secondary" data-rules-moved>
          The YARA and Sigma rules that fired on this sample are on{" "}
          <Link href={`/analysis/${report.job_id}/indicators#detection`} className="text-accent-strong hover:underline">
            Indicators &amp; detection
          </Link>
          .
        </p>
      )}

      {/* Carved payloads lead the tab: a nested executable inside a dropper is
        * the actual malware. The rows are under Resources. */}
      {carved.length > 0 && (
        <p className="rounded border border-status-red/40 bg-status-red/5 px-3 py-2 text-xs text-text-primary" role="note">
          {carved.length} executable{carved.length === 1 ? " was" : "s were"} carved out of the sample — appended past
          the last section, or embedded in a resource.{" "}
          <button type="button" onClick={() => setTab("resources")} className="text-accent-strong hover:underline">
            Show under Resources
          </button>
        </p>
      )}

      <div id="structure" className="scroll-mt-16">
        <Section title={structureTitle} empty={structureEmpty}>
          <div className="flex flex-col gap-3 sm:flex-row">
            <VerticalTabs
              items={STRUCTURE_TABS.map((t) => ({ ...t, count: tabCount(t.key) }))}
              selected={tab}
              onSelect={setTab}
              label={structureTitle}
              panelId="structure-panel"
              idPrefix="structure-tab"
            />
            <div
              role="tabpanel"
              id="structure-panel"
              aria-labelledby={`structure-tab-${tab}`}
              className="min-w-0 flex-1 space-y-3"
            >
              {tab === "sections" && (
                <>
                  <ArtifactSections sections={slots.structure.sections} />
                  {showsExtractedSections && staticData && staticData.sections.length > 0 && (
                    <div {...scrollRegion("Sections")} className={`overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}>
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-border">
                            <Th>Name</Th>
                            <Th>VA</Th>
                            <Th>Virtual size</Th>
                            <Th>Raw size</Th>
                            {/* PointerToRawData. A carved payload reports a file
                                offset; without this column there is nothing to
                                match it against. */}
                            <Th>Raw offset</Th>
                            <Th>Entropy</Th>
                            <Th>Characteristics</Th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border-light">
                          {staticData.sections.slice(0, shownOf("sections")).map((s, i) => (
                            <tr key={`${s.name}-${i}`} className="hover:bg-bg-hover">
                              <td className="px-4 py-2 text-xs font-mono text-text-primary">
                                {s.name}
                                {s.is_suspicious && (
                                  <span className="ml-2 rounded bg-status-red/10 px-1.5 py-0.5 text-[11px] text-status-red">suspicious</span>
                                )}
                              </td>
                              <td className="px-4 py-2 text-xs font-mono text-text-secondary">{s.virtual_address}</td>
                              <td className="px-4 py-2 text-xs text-text-secondary">{formatBytes(s.virtual_size)}</td>
                              <td className="px-4 py-2 text-xs text-text-secondary">{formatBytes(s.raw_size)}</td>
                              <td className="px-4 py-2 text-xs font-mono text-text-secondary">
                                {typeof s.raw_offset === "number" ? `0x${s.raw_offset.toString(16)}` : "-"}
                              </td>
                              <td className={`px-4 py-2 text-xs font-mono ${entropyClass(s.entropy)}`}>{s.entropy.toFixed(3)}</td>
                              <td className="truncate px-4 py-2 text-xs font-mono text-text-muted" title={s.characteristics}>
                                {s.characteristics || "-"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      <ShowMoreRows shown={Math.min(shownOf("sections"), staticData.sections.length)} total={staticData.sections.length} onShow={show("sections")} step={STATIC_ROWS_STEP} />
                    </div>
                  )}
                </>
              )}

              {tab === "imports" && (
                <>
                  <ArtifactSections sections={slots.structure.imports} />
                  {showsImports && staticData && staticData.imports.length > 0 && (
                    <div {...scrollRegion("Imports")} className={`overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}>
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-border">
                            <Th>{importContainer}</Th>
                            <Th>Function</Th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border-light">
                          {staticData.imports.slice(0, shownOf("imports")).map((row, i) => (
                            <tr key={i} className="hover:bg-bg-hover">
                              <td className="px-4 py-2 text-xs font-mono text-text-secondary">{row.dll}</td>
                              <td className="px-4 py-2 text-xs font-mono text-text-primary">{row.function}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      <ShowMoreRows shown={Math.min(shownOf("imports"), staticData.imports.length)} total={staticData.imports.length} onShow={show("imports")} step={STATIC_ROWS_STEP} />
                    </div>
                  )}
                  {techniqueHits.length > 0 && (
                    <div className="space-y-2">
                      <h3 className="text-xs font-semibold text-text-secondary">ATT&amp;CK from imports ({techniqueCount})</h3>
                      <p className="text-[11px] text-text-muted">
                        Derived from the import table alone — no sandbox, no model. A row is an association, not a
                        finding: the last column is how much ordinary software the same rule fires on, measured over
                        the corpus it names, and it says nothing about how likely this sample is to be benign.
                      </p>
                      <div {...scrollRegion("ATT&CK from imports")} className={`overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}>
                        <table className="w-full">
                          <thead>
                            <tr className="border-b border-border">
                              <Th>Technique</Th>
                              <Th>Name</Th>
                              <Th>Rule</Th>
                              <Th>Confidence</Th>
                              <Th>Imports</Th>
                              <Th>Benign rate</Th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border-light">
                            {techniqueHits.slice(0, shownOf("hits")).map((h, i) => (
                              <tr key={i} className="hover:bg-bg-hover">
                                <td className="px-4 py-2 text-xs font-mono text-accent">{h.technique_id ?? "-"}</td>
                                <td className="px-4 py-2 text-xs text-text-primary">{h.name ?? "-"}</td>
                                <td className="px-4 py-2 text-xs text-text-secondary">{h.rule || "-"}</td>
                                <td className="px-4 py-2 text-xs font-mono text-text-secondary">
                                  {typeof h.confidence === "number" ? h.confidence.toFixed(2) : "-"}
                                </td>
                                <td className="px-4 py-2 text-xs font-mono text-text-muted">
                                  {(h.matched_apis ?? []).slice(0, 4).join(", ")}
                                  {(h.matched_apis ?? []).length > 4 && ` +${(h.matched_apis ?? []).length - 4}`}
                                </td>
                                {/* An unmeasured rule says so: a blank cell would read
                                    as a rule that never fires on anything benign. */}
                                <td className="px-4 py-2 text-xs text-text-secondary">{h.benign_rate || "not measured"}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                        <ShowMoreRows shown={Math.min(shownOf("hits"), techniqueHits.length)} total={techniqueHits.length} onShow={show("hits")} step={STATIC_ROWS_STEP} />
                      </div>
                    </div>
                  )}
                  {capabilityProfile.length > 0 && staticData && (
                    <div className="space-y-1.5">
                      <h3 className="text-xs font-semibold text-text-secondary">What the imports can do</h3>
                      <div className="flex flex-wrap items-center gap-1.5">
                        {capabilityProfile.map(([cat, count]) => {
                          const share = (staticData.api_capability_rates ?? {})[cat];
                          return (
                            <span key={cat} className="rounded bg-bg-hover px-1.5 py-0.5 font-mono text-[11px] text-text-secondary">
                              {cat} ×{count}
                              {typeof share === "number" && ` (${share.toFixed(1)}%)`}
                            </span>
                          );
                        })}
                        <EvidenceChips ids={staticData.api_capabilities_evidence_ids ?? []} />
                      </div>
                      {/* Said once rather than on every chip. */}
                      {staticData.api_capability_corpus && (
                        <p className="text-[11px] text-text-muted">
                          The bracketed share is how much of {staticData.api_capability_corpus} the category appears on;
                          it says nothing about how likely this sample is to be benign.
                        </p>
                      )}
                    </div>
                  )}
                </>
              )}

              {tab === "exports" && (
                <>
                  <ArtifactSections sections={slots.structure.exports} />
                  {showsExports && staticData && exportTotal > 0 && (
                    <div {...scrollRegion("Exports")} className={`overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}>
                      {/* With the ordinal and the address when the format tool
                          reported them: several exports sharing one address is
                          a fact the names alone hide. */}
                      {exportRows.length > 0 ? (
                        <table className="w-full">
                          <thead>
                            <tr className="border-b border-border">
                              <Th>Name</Th>
                              <Th>Ordinal</Th>
                              <Th>RVA</Th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border-light">
                            {exportRows.slice(0, shownOf("exports")).map((row, i) => (
                              <tr key={`${row.name}-${i}`} className="hover:bg-bg-hover">
                                <td className="px-4 py-2 font-mono text-xs text-text-secondary">{row.name || "(unnamed)"}</td>
                                <td className="px-4 py-2 font-mono text-xs text-text-muted">{row.ordinal ?? "-"}</td>
                                <td className="px-4 py-2 font-mono text-xs text-text-muted">{row.rva ?? "-"}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : (
                        <div className="flex flex-wrap gap-1 p-3">
                          {/* Two exports can share a name (forwarders, ordinals):
                              the key is the position, so neither is dropped. */}
                          {staticData.exports.slice(0, shownOf("exports")).map((e, i) => (
                            <span key={`${e}-${i}`} className="rounded bg-bg-active px-1.5 py-0.5 font-mono text-[11px] text-text-secondary">
                              {e}
                            </span>
                          ))}
                        </div>
                      )}
                      <ShowMoreRows shown={Math.min(shownOf("exports"), exportTotal)} total={exportTotal} onShow={show("exports")} step={STATIC_ROWS_STEP} />
                    </div>
                  )}
                </>
              )}

              {tab === "resources" && resources.length > 0 && (
                <div {...scrollRegion("Resources")} className={`overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}>
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border">
                        <Th>Type</Th>
                        <Th>Location</Th>
                        <Th>Size</Th>
                        <Th>Entropy</Th>
                        <Th>SHA-256</Th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-light">
                      {resources.slice(0, shownOf("resources")).map((p, i) => (
                        <tr key={i} className="hover:bg-bg-hover">
                          <td className={`px-4 py-2 text-xs font-mono ${p.carved ? "text-status-red" : "text-text-secondary"}`}>
                            {p.type ?? "-"}
                            {p.carved && <span className="ml-2 rounded bg-status-red/10 px-1.5 py-0.5 font-sans text-[11px]">carved</span>}
                          </td>
                          <td className="px-4 py-2 text-xs font-mono text-text-secondary">
                            {p.id ?? (typeof p.offset === "number" ? `0x${p.offset.toString(16)}` : "-")}
                            {p.source && <span className="text-text-muted"> ({p.source})</span>}
                          </td>
                          <td className="px-4 py-2 text-xs text-text-secondary">{typeof p.size === "number" ? formatBytes(p.size) : "-"}</td>
                          <td className={`px-4 py-2 text-xs font-mono ${typeof p.entropy === "number" ? entropyClass(p.entropy) : "text-text-muted"}`}>
                            {typeof p.entropy === "number" ? p.entropy.toFixed(2) : "-"}
                          </td>
                          <td className="max-w-[16rem] truncate px-4 py-2 text-xs font-mono text-text-muted" title={p.sha256 ?? ""}>
                            {p.sha256 ? `${p.sha256.slice(0, 24)}…` : "-"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <ShowMoreRows shown={Math.min(shownOf("resources"), resources.length)} total={resources.length} onShow={show("resources")} step={STATIC_ROWS_STEP} />
                </div>
              )}

              {tabCount(tab) === 0 && !(tab === "imports" && (techniqueHits.length > 0 || capabilityProfile.length > 0)) && (
                <p className="text-xs text-text-muted">Not found</p>
              )}
            </div>
          </div>
        </Section>
      </div>

      <div id="strings" className="scroll-mt-16">
        <Section title="Strings" count={strings.length || null} empty={strings.length === 0 && slots.strings.length === 0}>
          <div className="space-y-3">
            {strings.length > 0 && (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <input
                    type="search"
                    aria-label="Search strings"
                    placeholder="Search strings"
                    value={query}
                    onChange={(e) => {
                      setQuery(e.target.value);
                      show("strings")(STATIC_ROWS_STEP);
                    }}
                    className="h-7 w-56 max-w-full rounded border border-border bg-bg-deep px-2.5 text-xs text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none"
                  />
                  <div role="group" aria-label="String kind" className="flex flex-wrap gap-1">
                    {[{ kind: "all" as const, count: strings.length }, ...facets].map((f) => (
                      <button
                        key={f.kind}
                        type="button"
                        aria-pressed={stringKind === f.kind}
                        onClick={() => {
                          setStringKind(f.kind);
                          show("strings")(STATIC_ROWS_STEP);
                        }}
                        className={`rounded border px-2 py-0.5 text-[11px] ${
                          stringKind === f.kind ? "border-accent text-accent-strong" : "border-border text-text-secondary hover:text-text-primary"
                        }`}
                      >
                        {f.kind === "all" ? "All" : f.kind.replace(/_/g, " ")} {f.count}
                      </button>
                    ))}
                  </div>
                </div>
                {filteredStrings.length === 0 ? (
                  <p className="text-xs text-text-muted">No string matches.</p>
                ) : (
                  <div {...scrollRegion("Strings")} className={`overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}>
                    <table className="w-full">
                      <thead>
                        <tr className="border-b border-border">
                          <Th>Kind</Th>
                          <Th>Value</Th>
                          <Th>Notes</Th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border-light">
                        {filteredStrings.slice(0, shownOf("strings")).map((s, i) => (
                          <tr key={i} className="hover:bg-bg-hover">
                            <td className="whitespace-nowrap px-4 py-2 text-xs text-text-muted">{s.kind.replace(/_/g, " ")}</td>
                            <td className="px-4 py-2 text-xs font-mono text-status-blue break-all">{s.value}</td>
                            <td className="px-4 py-2 text-xs text-text-muted">{s.notes || "-"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                    <ShowMoreRows shown={Math.min(shownOf("strings"), filteredStrings.length)} total={filteredStrings.length} onShow={show("strings")} step={STATIC_ROWS_STEP} />
                  </div>
                )}
              </>
            )}
            <ArtifactSections sections={slots.strings} />
          </div>
        </Section>
      </div>

      <div id="decoded" className="scroll-mt-16">
        <Section title="Decoded strings and configuration" count={config.length || null} empty={config.length === 0}>
          <div {...scrollRegion("Decoded strings and configuration")} className={`-mx-4 -my-3 overflow-x-auto ${SCROLL_REGION_FOCUS}`}>
            <table className="w-full">
              <thead>
                <tr className="border-b border-border-light">
                  <Th>Key</Th>
                  <Th>Value</Th>
                  <Th>How it was obtained</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-light">
                {config.map((item, i) => (
                  <tr key={`${item.key}-${i}`} className="align-top hover:bg-bg-hover">
                    <td className="px-4 py-2 text-xs text-text-primary">{item.key}</td>
                    <td className="px-4 py-2">
                      <span className="flex items-start gap-2">
                        <code className="min-w-0 break-all font-mono text-xs text-text-secondary">{item.value}</code>
                        <CopyButton value={item.value} what={`configuration value ${item.key}`} />
                      </span>
                    </td>
                    <td className="px-4 py-2 text-xs text-text-muted">
                      {item.how_obtained}
                      {item.evidence_refs.length > 0 ? (
                        <EvidenceChips ids={item.evidence_refs} className="ml-1" />
                      ) : (
                        <span className="ml-2 text-[10px] italic">no evidence cited</span>
                      )}
                      {/* The report's own check, in the reader's words. */}
                      {uncitedConfig.has(i + 1) && (
                        <span className="ml-2 text-[10px] italic text-status-orange">
                          (the report&apos;s check found no evidence for this item)
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      </div>

      <div id="functions" className="scroll-mt-16">
        <Section title="Functions examined" empty={slots.functions.length === 0}>
          <div className="space-y-3">
            <ArtifactSections sections={slots.functions} />
          </div>
        </Section>
      </div>

      {report.job_id && (
        <div id="call-map" className="scroll-mt-16">
          <CallMap jobId={report.job_id} />
        </div>
      )}

      {slots.other.length > 0 && (
        <div id="static-other" className="scroll-mt-16 space-y-3">
          <h2 className="text-sm font-semibold text-text-primary">Other static findings</h2>
          <ArtifactSections sections={slots.other} />
        </div>
      )}

      {!staticData && (
        <p className="text-xs text-text-muted">
          No format-aware extractor produced a typed static block for this{" "}
          {fileType ? <code>{fileTypeLabel(fileType)}</code> : "sample"}.
        </p>
      )}
    </div>
  );
}
