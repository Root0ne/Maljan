/**
 * Where every part of a stored report is drawn on the analysis page.
 *
 * The page is six tabs. Nothing the report carries may be reachable on no
 * tab at all: a finding drawn nowhere is a finding lost, however complete the
 * report is (the completeness rule). Two maps say where each part goes, and
 * both are typed against the report's own shape, so a field added to the
 * report without a place on the page fails the build here rather than going
 * missing quietly; the completeness test walks a stored run against them.
 *
 * A place is a tab, optionally with the block it lands in (`behaviour#attack`),
 * or `header` for the strip above the tabs. `export` marks a part the page
 * does not draw but the Export menu's "Full analysis (JSON)" carries whole,
 * and `export:timeline` one the "Discussion timeline" download is built from;
 * neither was drawn before the page had six tabs either. `none` is a part of
 * the report record no surface of the console carries: the two ids the page
 * uses for its own addresses. The completeness test pins that list.
 */

import type { AgentFindingDTO, ReportDetailDTO } from "@/lib/api";
import type { JobRoster } from "@/types";
import type { EvidenceSection, MalwareReport } from "@/types/malware-report";
import { extraTabs } from "./extraTabs";
import type { AnalysisTabKey } from "./overview";
import { RENDERED_TABS, sectionHasContent, tabOfSection, type SectionPlacements, type SectionTab } from "./reportSections";

export type Place =
  | "header"
  | "export"
  | "export:timeline"
  | "none"
  | AnalysisTabKey
  | `${AnalysisTabKey}#${string}`;

/** Where each field of the structured report is drawn (the first place is the main one). */
export const REPORT_FIELD_PLACES: Record<keyof MalwareReport, readonly Place[]> = {
  schema_version: ["export"],
  generated_at: ["export"],
  verdict: ["header"],
  verdict_not_assessed: ["export"],
  overall_confidence: ["header"],
  malware_category: ["header"],
  severity: ["overview#summary", "header"],
  identity: ["header", "static#identity"],
  static: ["static#static"],
  directed_text: ["export"],
  dynamic: ["behaviour#dynamic", "behaviour#behaviours"],
  network: ["network#network"],
  persistence: ["behaviour#persistence", "behaviour#behaviours"],
  capability_matrix: ["behaviour#attack", "overview#findings"],
  ttp_mappings: ["behaviour#attack", "overview#findings"],
  attribution: ["indicators#attribution", "header"],
  executive_summary: ["overview#summary"],
  key_findings: ["overview#summary"],
  capabilities_narrative: ["overview#summary"],
  technical_analysis: ["behaviour#technical-analysis", "overview#configuration", "static#decoded"],
  c2_channels: ["behaviour#technical-analysis"],
  defensive_recommendations: ["overview#recommendations"],
  detection_signatures: ["indicators#generated-rules"],
  run_summary: ["evidence#run-quality"],
  sections: ["evidence"],
  reputation: ["static#identity"],
  enrichment_not_asked: ["export"],
  negotiation_summary: ["evidence#debate"],
  stix_bundle_extended: ["indicators#stix"],
  judge_indicators: ["indicators#iocs"],
  consolidated_iocs: ["indicators#iocs"],
  misp_attributes: ["export"],
  references: ["export"],
  degraded_mode: ["header", "evidence#run-quality"],
  degradation_reasons: ["header", "evidence#run-quality"],
  operator_choices: ["evidence#run-quality"],
  flagged_statements: ["evidence#run-quality"],
  claims_not_discussed: ["evidence#run-quality"],
  question_answers: ["overview#questions"],
};

/** Where each field of the report record around it is drawn. */
export const REPORT_DTO_PLACES: Record<keyof ReportDetailDTO, readonly Place[]> = {
  id: ["none"],
  job_id: ["none"],
  verdict: ["header"],
  verdict_reading: ["header", "evidence#run-quality"],
  overall_confidence: ["header"],
  malware_category: ["header"],
  stix_bundle: ["indicators#stix"],
  mitre_techniques: ["behaviour#attack"],
  agent_reports: ["evidence#debate"],
  negotiation_log: ["evidence#debate", "export:timeline"],
  run_summary: ["evidence#run-quality"],
  agent_findings: ["evidence#conversation", "behaviour#behaviours", "indicators#rule-matches"],
  transcript: ["evidence#conversation"],
  malware_report: ["overview"],
  section_tabs: ["evidence"],
  incomplete_reason: ["header"],
  created_at: ["header"],
};

/** The block each section tab of `reportSections` now lives on. A dynamic
 *  section is drawn among the behaviours, except the process list the sandbox
 *  wrote, which sits under the process tree it repeats (`behaviour#dynamic`). */
export const SECTION_TAB_PLACE: Record<SectionTab, Place> = {
  identity: "static#identity",
  static: "static#static",
  dynamic: "behaviour#behaviours",
  network: "network#network",
  persistence: "behaviour#persistence",
  detection: "indicators#rule-matches",
  other: "evidence",
};

/** The route key of the block each section tab used to be a tab of its own as. */
export const SECTION_TAB_BLOCK: Record<Exclude<SectionTab, "other">, string> = {
  identity: "/identity",
  static: "/static",
  dynamic: "/dynamic",
  network: "/network",
  persistence: "/persistence",
  detection: "/detection",
};

/**
 * Where one section is drawn: on the block its key or the report places it
 * on, else on its agent's or server's view under Evidence, else in the
 * Evidence records' footer of sections no tab draws. Never nowhere.
 */
export function sectionPlace(
  section: EvidenceSection,
  placed: SectionPlacements,
  findings: readonly AgentFindingDTO[] | null | undefined,
  roster?: JobRoster | null,
  all?: EvidenceSection[] | null,
): Place {
  const tab = tabOfSection(section.key, placed);
  if (RENDERED_TABS.has(tab)) return SECTION_TAB_PLACE[tab];
  const view = extraTabs(all ?? [section], placed, findings, roster).find((t) => t.sections.includes(section));
  return view ? `evidence#${view.key}` : "evidence#unrouted";
}

/** Every section of a report with content, with the place it is drawn. */
export function sectionPlaces(
  report: ReportDetailDTO,
  roster?: JobRoster | null,
): { section: EvidenceSection; place: Place }[] {
  const sections = report.malware_report?.sections ?? [];
  return sections
    .filter(sectionHasContent)
    .map((section) => ({
      section,
      place: sectionPlace(section, report.section_tabs, report.agent_findings, roster, sections),
    }));
}
