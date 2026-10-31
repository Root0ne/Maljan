/**
 * The views a run adds under its Evidence tab for what an operator
 * connected: one per agent of its own and one per tool server whose output no
 * other tab draws. (They were top-level tabs of their own once; an analysis
 * now has six fixed tabs, and these are sub-views of the sixth.)
 *
 * The fixed tabs were written against the agents and servers the platform
 * ships. An agent an operator defines (a generic one, a lead) and a server
 * nobody here knows reached the console in two places only: a row in the
 * discussion and the evidence footer of sections no tab draws. So a run
 * offers a view named after each of them, when it has something to put there
 * (the same promise `analysisTabs` makes for every block).
 *
 * Everything is read from what the run recorded: the roster (role, stages),
 * the agents' findings, and each section's `source` and `source_server`. No
 * agent's or server's name is ever tested for. A server's tab is labelled by
 * the display name the roster gives it (`servers`), else by its key.
 *
 * What goes where, in this order, for a section no fixed tab draws:
 *  1. it names (`agent:<name>`, `artifact:<a>, <b>`) an agent of the run that
 *     has a tab: that agent's tab;
 *  2. it carries a `source_server`: that server's tab;
 *  3. otherwise it stays in the EVIDENCE footer.
 * A section the report placed on a fixed tab (`section_tabs`, which carries
 * `AgentDefinition.tab`) is never moved. An agent whose role has a tab of its
 * own (static, dynamic, network, judge) or whose stage is triage, verdict or
 * report is a built-in's and gets none.
 */

import type { AgentFindingDTO, ReportDetailDTO } from "@/lib/api";
import type { JobRoster } from "@/types";
import type { EvidenceSection } from "@/types/malware-report";
import {
  dynamicAnalystClaims,
  type AnalystClaim,
  type AnalystClaims,
} from "./dynamicClaims";
import {
  RENDERED_TABS,
  sectionHasContent,
  tabOfSection,
  type SectionPlacements,
} from "./reportSections";

export type ExtraTabKind = "agent" | "server";

export interface ExtraTab {
  kind: ExtraTabKind;
  /** The agent key or the server name. */
  id: string;
  /** The path suffix under `/analysis/{id}`. */
  key: string;
  label: string;
  /** What the agent concluded, in full; `null` on a server's tab. */
  claims: AnalystClaims | null;
  sections: EvidenceSection[];
}

/** The roles an operator's own agent has; every other role has a home elsewhere. */
const OPERATOR_ROLES: ReadonlySet<string> = new Set(["generic", "lead"]);
/** The stage kinds the platform's own steps run in. */
const BUILTIN_STAGE_KINDS: ReadonlySet<string> = new Set([
  "triage",
  "verdict",
  "report",
]);

/** One path segment for an id; an id of dots alone is encoded, as a URL would resolve it away. */
function segment(id: string): string {
  const encoded = encodeURIComponent(id);
  return /^\.+$/.test(encoded) ? encoded.replace(/\./g, "%2E") : encoded;
}

export function agentTabKey(agent: string): string {
  return `/agent/${segment(agent)}`;
}

export function serverTabKey(server: string): string {
  return `/server/${segment(server)}`;
}

/**
 * The tab a route's `key` param names. The param is matched as handed over
 * first and decoded only when that finds nothing, so an id holding a `%` is
 * never decoded twice whichever form the framework gives.
 */
export function tabByParam(
  tabs: readonly ExtraTab[],
  kind: ExtraTabKind,
  param: string,
): ExtraTab | undefined {
  const ofKind = tabs.filter((t) => t.kind === kind);
  const exact = ofKind.find((t) => t.id === param);
  if (exact) return exact;
  try {
    const decoded = decodeURIComponent(param);
    return ofKind.find((t) => t.id === decoded);
  } catch {
    return undefined;
  }
}

/**
 * Labels that say apart what they name: a label equal, ignoring case, to a
 * fixed tab's or to another extra tab's gets its kind added
 * (`network (server)`).
 */
export function disambiguate(
  tabs: readonly ExtraTab[],
  taken: readonly string[],
): ExtraTab[] {
  const count = new Map<string, number>();
  for (const tab of tabs) {
    const key = tab.label.toLowerCase();
    count.set(key, (count.get(key) ?? 0) + 1);
  }
  const fixed = new Set(taken.map((l) => l.toLowerCase()));
  return tabs.map((tab) => {
    const key = tab.label.toLowerCase();
    const clash = fixed.has(key) || (count.get(key) ?? 0) > 1;
    return clash ? { ...tab, label: `${tab.label} (${tab.kind})` } : tab;
  });
}

/** The roster agents that get a tab of their own, in roster order. */
function operatorAgents(roster: JobRoster | null | undefined) {
  const builtinStage = new Set<string>();
  for (const stage of roster?.stages ?? []) {
    if (BUILTIN_STAGE_KINDS.has(stage.kind))
      for (const key of stage.agents) builtinStage.add(key);
  }
  return (roster?.agents ?? []).filter(
    (agent) =>
      OPERATOR_ROLES.has((agent.role ?? "").toLowerCase()) &&
      !builtinStage.has(agent.key),
  );
}

/** The agents a section names as its authors, in the order it names them. */
export function agentsOfSource(source: string | null | undefined): string[] {
  const text = (source ?? "").trim();
  for (const prefix of ["agent:", "artifact:"]) {
    if (text.startsWith(prefix)) {
      return text
        .slice(prefix.length)
        .split(",")
        .map((name) => name.trim())
        .filter(Boolean);
    }
  }
  return [];
}

/** The sections no fixed tab draws, with content, in the order the run gathered them. */
function unplaced(
  sections: EvidenceSection[] | null | undefined,
  placed?: SectionPlacements,
): EvidenceSection[] {
  return (sections ?? []).filter(
    (section) =>
      sectionHasContent(section) &&
      !RENDERED_TABS.has(tabOfSection(section.key, placed)),
  );
}

/**
 * Every extra tab this run offers: agents first, in roster order, then
 * servers, in the order their first section appears. A tab with nothing to
 * draw is not offered.
 */
export function extraTabs(
  sections: EvidenceSection[] | null | undefined,
  placed: SectionPlacements,
  findings: readonly AgentFindingDTO[] | null | undefined,
  roster?: JobRoster | null,
): ExtraTab[] {
  const agents = operatorAgents(roster);
  const owners = new Set(agents.map((agent) => agent.key));
  // What DYNAMIC already draws is not drawn twice.
  const onDynamic = new Set(
    dynamicAnalystClaims(findings, roster).map((f) => f.agent),
  );

  const agentSections = new Map<string, EvidenceSection[]>();
  const serverSections = new Map<string, EvidenceSection[]>();
  for (const section of unplaced(sections, placed)) {
    const author = agentsOfSource(section.source).find((name) =>
      owners.has(name),
    );
    const server = (section.source_server ?? "").trim();
    const into = author ? agentSections : server ? serverSections : null;
    const id = author ?? server;
    if (!into || !id) continue;
    into.set(id, [...(into.get(id) ?? []), section]);
  }

  const tabs: ExtraTab[] = [];
  for (const agent of agents) {
    const found = (findings ?? []).filter(
      (f) => f.agent_name === agent.key && !onDynamic.has(f.agent_name),
    );
    // Every claim of the agent, across all of its findings, not the first.
    const claims = found.flatMap((f) => (f.claims ?? []) as AnalystClaim[]);
    const own = agentSections.get(agent.key) ?? [];
    if (claims.length === 0 && own.length === 0) continue;
    tabs.push({
      kind: "agent",
      id: agent.key,
      key: agentTabKey(agent.key),
      label: agent.label || agent.key,
      claims: claims.length > 0 ? { agent: agent.key, claims } : null,
      sections: own,
    });
  }
  const serverLabels = roster?.servers ?? {};
  for (const [server, own] of serverSections) {
    tabs.push({
      kind: "server",
      id: server,
      key: serverTabKey(server),
      label: serverLabels[server] || server,
      claims: null,
      sections: own,
    });
  }
  return tabs;
}

export interface EvidenceView {
  /** The path suffix under the Evidence tab; empty for the tab's first view. */
  key: string;
  label: string;
  kind: "bundle" | "records" | "conversation" | ExtraTabKind;
}

/** The views every analysis with a report has under Evidence: the evidence
 *  bundle first, then every tool call's record, then the discussion. */
export const EVIDENCE_VIEWS: readonly EvidenceView[] = [
  { key: "", label: "Evidence bundle", kind: "bundle" },
  { key: "/records", label: "Records", kind: "records" },
  { key: "/conversation", label: "Analyst discussion", kind: "conversation" },
];

/** Before a report exists there is no bundle: the records lead, as they fill
 *  while the run works. */
export const RUNNING_EVIDENCE_VIEWS: readonly EvidenceView[] = [
  { key: "", label: "Records", kind: "records" },
  { key: "/conversation", label: "Analyst discussion", kind: "conversation" },
];

/**
 * The views under the Evidence tab: the evidence bundle, the records, the
 * analysts' discussion, then one per agent and server of the run's own that
 * has something to draw (`extraTabs`), in that order. An agent or a server
 * never gets a top-level tab of its own.
 */
export function evidenceViews(
  report: ReportDetailDTO | null | undefined,
  roster?: JobRoster | null,
): EvidenceView[] {
  if (!report) return [...RUNNING_EVIDENCE_VIEWS];
  const extra = disambiguate(
    extraTabs(report.malware_report?.sections, report.section_tabs, report.agent_findings, roster),
    EVIDENCE_VIEWS.map((v) => v.label),
  ).map((tab): EvidenceView => ({ key: tab.key, label: tab.label, kind: tab.kind }));
  return [...EVIDENCE_VIEWS, ...extra];
}

/** The sections no tab draws at all: what the Evidence records' footer keeps. */
export function unroutedSections(
  sections: EvidenceSection[] | null | undefined,
  placed: SectionPlacements,
  findings: readonly AgentFindingDTO[] | null | undefined,
  roster?: JobRoster | null,
): EvidenceSection[] {
  const drawn = new Set(
    extraTabs(sections, placed, findings, roster).flatMap((t) => t.sections),
  );
  return unplaced(sections, placed).filter((section) => !drawn.has(section));
}
