/**
 * Which tabs an analysis offers, and why each one is there.
 *
 * A tab is a promise that there is something behind it. The console used to
 * offer all twelve on every run and let ten of them apologise — "No dynamic
 * analysis data available", "No persistence mechanisms identified" — which
 * spends a reader's attention on finding out that nothing happened.
 *
 * So a tab is offered only when this run produced what it draws. Two rules
 * decide, and both are read from the report rather than from configuration: a
 * ledger-built section routed to that tab carries content
 * (`reportSections.sectionsForTab`), or the tab's own typed block does. A
 * configured-but-silent tool must not draw a tab any more than it draws a
 * header.
 *
 * Three tabs are unconditional and each for its own reason. SUMMARY is where
 * a run lands, CONVERSATION is offered whatever state the job is in (it is the
 * run happening as much as the run recorded), and EVIDENCE is the ledger every
 * citation resolves into — "no call matches these filters" is information
 * there, not an apology.
 */

import type { ReportDetailDTO } from "@/lib/api";
import { sectionsForTab } from "./reportSections";
import type { MalwareReport } from "@/types/malware-report";

export type TabGroup = "overview" | "analysis" | "intel" | "advanced";

export interface TabDef {
  /** Path suffix under `/analysis/{id}`; the empty string is SUMMARY. */
  key: string;
  label: string;
  group: TabGroup;
  /** The lucide icon name this tab is drawn with. */
  icon: TabIcon;
}

export type TabIcon =
  | "summary"
  | "conversation"
  | "identity"
  | "static"
  | "dynamic"
  | "network"
  | "persistence"
  | "attack"
  | "attribution"
  | "detection"
  | "defense"
  | "evidence";

export const TABS: TabDef[] = [
  { key: "", label: "SUMMARY", group: "overview", icon: "summary" },
  // The run as it happens and as it happened: one route for both, which is
  // what replaced the old LIVE and PROCESS pair.
  { key: "/conversation", label: "CONVERSATION", group: "overview", icon: "conversation" },
  { key: "/identity", label: "IDENTITY", group: "overview", icon: "identity" },
  { key: "/static", label: "STATIC", group: "analysis", icon: "static" },
  { key: "/dynamic", label: "DYNAMIC", group: "analysis", icon: "dynamic" },
  { key: "/network", label: "NETWORK", group: "analysis", icon: "network" },
  { key: "/persistence", label: "PERSISTENCE", group: "analysis", icon: "persistence" },
  { key: "/capabilities", label: "ATT&CK", group: "intel", icon: "attack" },
  { key: "/attribution", label: "ATTRIBUTION", group: "intel", icon: "attribution" },
  // SIGNATURES + RULES merged into one DETECTION tab, which also folds the
  // STIX export bundle in as a third section.
  { key: "/detection", label: "DETECTION", group: "intel", icon: "detection" },
  { key: "/defense", label: "DEFENSE", group: "intel", icon: "defense" },
  // The ledger every other tab cites. A citation chip anywhere in the report
  // links straight to one of its rows.
  { key: "/evidence", label: "EVIDENCE", group: "advanced", icon: "evidence" },
];

export const TAB_GROUP_ORDER: TabGroup[] = ["overview", "analysis", "intel", "advanced"];

/** The three tabs a run offers before it has produced anything. */
const ALWAYS: ReadonlySet<string> = new Set(["", "/conversation", "/evidence"]);

function nonEmpty(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (value && typeof value === "object") return Object.keys(value).length > 0;
  return Boolean(value);
}

/** The claims of every analyst whose domain or name is `domain`. */
function analystClaims(report: ReportDetailDTO, domain: string): boolean {
  return (report.agent_findings ?? []).some(
    (finding) =>
      (finding.domain?.toLowerCase() === domain ||
        finding.agent_name?.toLowerCase().includes(domain)) &&
      (finding.claims?.length ?? 0) > 0,
  );
}

/** Whether a deterministic rule layer recorded a match on this run. */
export function hasRuleMatches(report: ReportDetailDTO | null | undefined): boolean {
  if (!report) return false;
  return (report.agent_findings ?? []).some(
    (finding) =>
      (finding.agent_name === "yara_layer" || finding.agent_name === "sigma_layer") &&
      (finding.claims?.length ?? 0) > 0,
  );
}

function attributionSaysSomething(mr: MalwareReport | null): boolean {
  const attribution = mr?.attribution;
  if (!attribution) return false;
  return Boolean(
    attribution.family ||
      attribution.actor ||
      attribution.campaign ||
      nonEmpty(attribution.similar_samples) ||
      nonEmpty(attribution.function_hash_matches) ||
      nonEmpty(attribution.family_rag_candidates),
  );
}

/**
 * Whether one tab has something of this run to draw.
 *
 * Exported for its own test: the twelve answers below are the whole of the
 * rule, and each is a sentence about what the run produced rather than about
 * what the console can render.
 */
export function tabHasContent(key: string, report: ReportDetailDTO | null): boolean {
  if (ALWAYS.has(key)) return true;
  if (!report) return false;

  const mr = report.malware_report;
  const sections = mr?.sections;

  switch (key) {
    case "/identity":
      // The sample's own facts: the identity block, or a header table from
      // whichever binary-info tool ran.
      return Boolean(mr?.identity) || sectionsForTab(sections, "identity").length > 0;
    case "/static":
      return Boolean(mr?.static) || sectionsForTab(sections, "static").length > 0;
    case "/dynamic":
      // A sandbox report, what the ledger's sandbox tools returned, or the
      // dynamic analyst's own conclusion about a detonation that produced
      // nothing — a run where the analyst worked is not an empty run.
      return (
        Boolean(mr?.dynamic) ||
        sectionsForTab(sections, "dynamic").length > 0 ||
        analystClaims(report, "dynamic")
      );
    case "/network":
      // A capture or a sandbox network channel, and the endpoints carved out
      // of the binary's own strings when neither ran.
      return (
        Boolean(mr?.network) ||
        sectionsForTab(sections, "network").length > 0 ||
        (mr?.static?.interesting_strings ?? []).some(
          (s) => s.kind === "domain" || s.kind === "ip" || s.kind === "url",
        )
      );
    case "/persistence":
      return nonEmpty(mr?.persistence) || sectionsForTab(sections, "persistence").length > 0;
    case "/capabilities":
      // Techniques the run mapped, or the corroboration table that says which
      // deterministic source asserted each of them.
      return (
        nonEmpty(mr?.ttp_mappings) ||
        nonEmpty(mr?.capability_matrix) ||
        nonEmpty(report.mitre_techniques) ||
        nonEmpty(report.run_summary?.corroboration)
      );
    case "/attribution":
      return attributionSaysSomething(mr);
    case "/detection":
      // Rules that fired, rules the run wrote, and the STIX bundle it exports.
      return (
        hasRuleMatches(report) ||
        nonEmpty(mr?.detection_signatures) ||
        nonEmpty(mr?.stix_bundle_extended) ||
        nonEmpty(report.stix_bundle)
      );
    case "/defense":
      return nonEmpty(mr?.defensive_recommendations);
    default:
      // A tab nothing here names is offered once there is a report, so adding
      // one to `TABS` without a rule costs a reader nothing.
      return true;
  }
}

/** The tabs this run offers, in the declared order. */
export function tabsFor(report: ReportDetailDTO | null): TabDef[] {
  return TABS.filter((tab) => tabHasContent(tab.key, report));
}
