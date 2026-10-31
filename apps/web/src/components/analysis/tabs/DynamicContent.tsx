"use client";

import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import { useState } from "react";

import { useReport } from "@/components/analysis/AnalysisContext";
import type { ReportDetailDTO } from "@/lib/api";
import type { EvidenceSection, SandboxSignature } from "@/types/malware-report";
import { runSignatureScale } from "@/lib/severity";
import Section from "@/components/ui/Section";
import ShowMoreRows from "@/components/ui/ShowMoreRows";
import { SeverityPill, Tag } from "@/components/ui/Pill";
import Th from "@/components/ui/Th";
import { ArtifactSections } from "@/components/analysis/ArtifactTable";
import { hasSection, sectionsForTab } from "@/components/analysis/reportSections";
import { dynamicAnalystClaims } from "@/components/analysis/dynamicClaims";
import AnalystFindings from "@/components/analysis/AnalystFindings";
import {
  signatureGroups,
  viewKeeps,
  type BehaviourView,
  type SignatureRow,
} from "@/components/analysis/behaviourView";
import { StructuredCell } from "@/components/analysis/StructuredValue";
import ProcessTree from "./ProcessTree";
import PersistenceList from "./PersistenceContent";
import type { JobRoster } from "@/types";

/** How many rows the registry, file and API tables draw before offering more. */
const STEP = 10;

/* D10: detect anti-emulation / anti-VM / anti-debug signatures so the empty
 * process-tree state can explain why the sandbox traced nothing. Mirrors the
 * regex used by the worker's degradation_reasons builder
 * (src/maljan/pipeline/nodes.py), so the banner copy and this hint stay in
 * lockstep. */
const ANTI_EMU_RE =
  /emulation|anti[\s_-]?vm|anti[\s_-]?debug|sandbox\s*detect|qemu|virtualbox|vmware|hyper[\s_-]?v/i;

function antiEmulationHit(signatures: readonly SandboxSignature[]): SandboxSignature | undefined {
  return signatures.find((s) => ANTI_EMU_RE.test(s.name) || ANTI_EMU_RE.test(s.description ?? ""));
}

/** Sections that say the same as one of this tab's typed views, kept one click away. */
function ToolOutput({ sections }: { sections: EvidenceSection[] }) {
  if (sections.length === 0) return null;
  return (
    <details className="group">
      <summary className="cursor-pointer text-xs text-text-secondary hover:text-text-primary">
        The same, as the tools returned it ({sections.length})
      </summary>
      <div className="mt-2 space-y-3">
        <ArtifactSections sections={sections} />
      </div>
    </details>
  );
}

/**
 * The process tree, with the sample's path open (`ProcessTree`). A run whose
 * sandbox traced nothing because the sample detected it says so; a run that
 * was not detonated says that.
 */
export function ProcessesBlock({ report }: { report: ReportDetailDTO }) {
  const mr = report.malware_report;
  const dyn = mr?.dynamic;
  const tree = dyn?.process_tree ?? [];
  const evasion = antiEmulationHit(dyn?.sandbox_signatures ?? []);
  const covering = sectionsForTab(mr?.sections, "dynamic", report.section_tabs).filter(
    (s) => s.key === "sandbox_processes",
  );
  const empty = tree.length === 0 && !evasion && covering.length === 0;
  return (
    <Section
      title="Process tree"
      count={tree.length > 0 ? tree.length : null}
      empty={empty}
      emptyText={dyn ? "Not found" : "Not detonated on this run"}
    >
      <div className="space-y-3">
        {tree.length > 0 ? (
          <ProcessTree roots={tree} mr={mr} />
        ) : evasion ? (
          /* An empty tree is drawn only where the run can say why it is
           * empty: a sample that detected the sandbox and left is a finding,
           * and "no process activity recorded" beside nothing is not. */
          <p className="text-xs text-text-muted">
            Sandbox traced no process activity — sample employed anti-emulation behaviour
            <span className="ml-1 text-status-orange">({evasion.name})</span>.
          </p>
        ) : null}
        {tree.length > 0 ? (
          <ToolOutput sections={covering} />
        ) : (
          <ArtifactSections sections={covering} />
        )}
      </div>
    </Section>
  );
}

/**
 * What the sample did: the sandbox's signatures by severity, then by ATT&CK
 * technique; the persistence it established; and the registry, file and API
 * activity the sandbox recorded. `view` keeps only what is under one tactic.
 */
export function BehavioursBlock({
  report,
  roster,
  view,
  tactics,
}: {
  report: ReportDetailDTO;
  roster?: JobRoster | null;
  view: BehaviourView;
  tactics: ReadonlyMap<string, ReadonlySet<string>>;
}) {
  const { showEvidence } = useReport();
  const [shown, setShown] = useState<Record<string, number>>({});
  const shownOf = (t: string) => shown[t] ?? STEP;
  const show = (t: string) => (n: number) => setShown((s) => ({ ...s, [t]: n }));

  const mr = report.malware_report;
  const dyn = mr?.dynamic ?? null;
  const reportSections = mr?.sections;
  const analystFindings = dynamicAnalystClaims(report.agent_findings, roster);
  const dynamicSections = sectionsForTab(reportSections, "dynamic", report.section_tabs);
  const covering = dynamicSections.filter((s) => s.key === "sandbox_signatures");
  const otherSections = dynamicSections.filter((s) => s.key !== "sandbox_signatures" && s.key !== "sandbox_processes");
  const persistenceSections = sectionsForTab(reportSections, "persistence", report.section_tabs);
  const persistence = mr?.persistence ?? [];

  /* The scale the run recorded for its sandbox report, which is what says
   * what a signature's number means (`signatureScore`); a run recorded before
   * scales were is read by the legacy table. */
  const scale = runSignatureScale(report.run_summary);
  const signatures = (dyn?.sandbox_signatures ?? []).filter((s) => viewKeeps(view, s.technique_ids ?? [], tactics));
  const groups = signatureGroups(signatures, scale);
  const keptPersistence = view === "defence-evasion" ? [] : persistence;
  // The registry exists on Windows and nowhere else; the table is drawn from
  // evidence — typed rows or a registry section — never from the platform.
  const showsRegistry = Boolean(dyn?.registry_mods.length) || hasSection(reportSections, "sandbox_registry");

  const empty =
    !dyn &&
    analystFindings.length === 0 &&
    dynamicSections.length === 0 &&
    persistence.length === 0 &&
    persistenceSections.length === 0;

  const openSignature = (row: SignatureRow, opener: HTMLElement) =>
    showEvidence?.(
      {
        title: row.signature.name,
        severity: row.rung,
        category: `Sandbox signature · ${row.sandboxText}${row.scale ? ` on the ${row.scale} scale` : ""}`,
        details: [row.signature.description, ...row.signature.marks].filter((d) => Boolean(d && d.trim())),
        techniques: row.signature.technique_ids,
        evidenceIds: [],
      },
      opener,
    );

  return (
    <Section title="Behaviours" count={signatures.length + keptPersistence.length || null} empty={empty}>
      <div className="space-y-5">
        {view === "all" && analystFindings.length > 0 && <AnalystFindings findings={analystFindings} />}

        {!dyn && view === "all" && (
          <p className="text-sm text-text-secondary">
            The sample was not detonated on this run, so there is no behaviour to show.
          </p>
        )}

        {dyn?.unavailable && dyn.unavailable.length > 0 && view === "all" && (
          <p className="text-xs text-text-muted">Not provided by this sandbox: {dyn.unavailable.join(", ")}.</p>
        )}

        {dyn && (
          <div className="space-y-3" aria-label="Sandbox signatures" role="group">
            {groups.length === 0 && (
              <p className="text-xs text-text-muted">
                {view === "all" ? "No sandbox signature fired." : "No sandbox signature under this tactic."}
              </p>
            )}
            {groups.map((group) => (
              <div key={group.rung ?? "unrated"} className="space-y-2">
                <h3 className="flex items-center gap-2 text-xs font-semibold text-text-secondary">
                  <SeverityPill severity={group.rung} />
                  <span>
                    {group.count} signature{group.count === 1 ? "" : "s"}
                  </span>
                </h3>
                <ul className="divide-y divide-border-light rounded border border-border-light">
                  {group.techniques.map((t) =>
                    t.rows.map((row, i) => (
                      <li key={`${t.technique}-${i}`} className="flex items-start gap-3 px-3 py-2">
                        <span className="w-20 shrink-0 font-mono text-[11px] text-status-blue">
                          {i === 0 ? t.technique || "No technique" : ""}
                        </span>
                        <div className="min-w-0 flex-1">
                          <button
                            type="button"
                            onClick={(e) => openSignature(row, e.currentTarget)}
                            className="text-left text-sm font-medium text-text-primary hover:underline"
                          >
                            {row.signature.name}
                          </button>
                          {row.signature.description && (
                            <p className="mt-0.5 text-xs text-text-secondary">{row.signature.description}</p>
                          )}
                          <p className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-text-muted">
                            <span title={row.scale ? `${row.sandboxText} on the ${row.scale} scale` : "The sandbox's own number; its scale is not recorded for this run"}>
                              Sandbox: {row.sandboxText}
                            </span>
                            {row.signature.technique_ids.slice(1).map((tid) => (
                              <Tag key={tid}>{tid}</Tag>
                            ))}
                            {row.signature.marks.length > 0 && (
                              <span>
                                · {row.signature.marks.length} evidence mark{row.signature.marks.length === 1 ? "" : "s"}
                              </span>
                            )}
                          </p>
                        </div>
                      </li>
                    )),
                  )}
                </ul>
              </div>
            ))}
            <ToolOutput sections={covering} />
          </div>
        )}
        {!dyn && <ArtifactSections sections={covering} />}

        {view !== "defence-evasion" && (
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-text-secondary">
              Persistence mechanisms{keptPersistence.length > 0 ? ` (${keptPersistence.length})` : ""}
            </h3>
            {keptPersistence.length === 0 && persistenceSections.length === 0 ? (
              <p className="text-xs text-text-muted">Not found</p>
            ) : (
              <PersistenceList items={keptPersistence} sections={persistenceSections} />
            )}
          </div>
        )}

        {view === "all" && showsRegistry && dyn && dyn.registry_mods.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-xs font-semibold text-text-secondary">
              Registry modifications ({dyn.registry_mods.length})
            </h3>
            <div {...scrollRegion("Registry modifications")} className={`overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}>
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border">
                    <Th>Operation</Th>
                    <Th>Hive</Th>
                    <Th>Key</Th>
                    <Th>Value name</Th>
                    <Th>New value</Th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-light">
                  {dyn.registry_mods.slice(0, shownOf("registry")).map((r, i) => (
                    <tr key={i} className="hover:bg-bg-hover">
                      <td className="px-4 py-2 text-xs text-text-muted">{r.operation}</td>
                      <td className="px-4 py-2 text-xs font-mono text-text-secondary">{r.hive}</td>
                      <td className="px-4 py-2 text-xs font-mono text-status-blue break-all">{r.key}</td>
                      <td className="px-4 py-2 text-xs font-mono text-text-secondary">{r.value_name || "-"}</td>
                      <td className="px-4 py-2 text-xs text-text-secondary break-all">{r.new_value || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <ShowMoreRows
                shown={Math.min(shownOf("registry"), dyn.registry_mods.length)}
                total={dyn.registry_mods.length}
                onShow={show("registry")}
                step={STEP}
              />
            </div>
          </div>
        )}

        {view === "all" && dyn && dyn.file_operations.length > 0 && (
          <RecordTable
            title="File operations"
            rows={dyn.file_operations}
            shown={shownOf("files")}
            onShow={show("files")}
          />
        )}

        {view === "all" && dyn && dyn.notable_apis.length > 0 && (
          <RecordTable
            title="Notable API calls"
            rows={dyn.notable_apis}
            shown={shownOf("apis")}
            onShow={show("apis")}
          />
        )}

        {view === "all" && <ArtifactSections sections={otherSections} />}
      </div>
    </Section>
  );
}

/** A cell: a plain value as it is, a nested one laid out (`StructuredCell`), an empty one as a dash. */
function Cell({ value, name }: { value: unknown; name: string }) {
  if (value === null || value === undefined || value === "") return <>-</>;
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return <>{String(value)}</>;
  return <StructuredCell value={value} name={name} />;
}

/**
 * Records of no declared shape (the sandbox's file operations and API calls),
 * drawn as a table headed by the keys the records use, in the order they
 * first appear, rather than as a dump of JSON.
 */
function RecordTable({
  title,
  rows,
  shown,
  onShow,
}: {
  title: string;
  rows: Record<string, unknown>[];
  shown: number;
  onShow: (n: number) => void;
}) {
  const columns: string[] = [];
  for (const row of rows) {
    for (const key of Object.keys(row ?? {})) if (!columns.includes(key)) columns.push(key);
  }
  return (
    <div className="space-y-2">
      <h3 className="text-xs font-semibold text-text-secondary">
        {title} ({rows.length})
      </h3>
      <div {...scrollRegion(title)} className={`overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}>
        <table className="w-full">
          <thead>
            <tr className="border-b border-border">
              {columns.map((c) => (
                <Th key={c}>{c.replace(/_/g, " ")}</Th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border-light">
            {rows.slice(0, shown).map((row, i) => (
              <tr key={i} className="hover:bg-bg-hover">
                {columns.map((c) => (
                  <td key={c} className="px-4 py-2 align-top text-xs font-mono text-text-secondary break-all">
                    <Cell value={row?.[c]} name={`${title}, row ${i + 1}, ${c}`} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        <ShowMoreRows shown={Math.min(shown, rows.length)} total={rows.length} onShow={onShow} step={STEP} />
      </div>
    </div>
  );
}
