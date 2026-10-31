/**
 * Whether one block of the analysis has something of this run to draw.
 *
 * The analysis page has six tabs, each drawn on every finished run; the
 * blocks inside them are the pages the console used to offer as tabs of
 * their own (dynamic behaviour, persistence, ATT&CK, attribution, …). A block
 * the run never filled keeps its place and says "Not found" rather than
 * drawing an apology of its own, and the answer to "did the run fill it" is
 * this module's.
 *
 * Two rules decide, and both are read from the report rather than from
 * configuration: a ledger-built section routed to that block carries content
 * (`reportSections.sectionsForTab`), or the block's own typed field does. A
 * configured-but-silent tool must not fill a block any more than it draws a
 * header. The keys are the old tabs' path suffixes, which is also where their
 * routes now redirect from (next.config.ts).
 */

import type { ReportDetailDTO } from "@/lib/api";
import { hasMappedTechniques } from "./capabilityHeatmap";
import { sectionsForTab } from "./reportSections";
import { hasIndicators } from "./indicators";
import { hasRuleMatches } from "./ruleMatches";
import { dynamicAnalystClaims } from "./dynamicClaims";
import type { JobRoster } from "@/types";
import type { MalwareReport } from "@/types/malware-report";

/** The blocks that answer something whatever the run produced. */
const ALWAYS: ReadonlySet<string> = new Set(["", "/conversation", "/evidence"]);

function nonEmpty(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (value && typeof value === "object") return Object.keys(value).length > 0;
  return Boolean(value);
}

/**
 * Whether the attribution block named anything.
 *
 * Exported because the tab draws itself on the same answer: the block is on
 * every report, so its presence says nothing and only its content does.
 */
export function attributionSaysSomething(mr: MalwareReport | null | undefined): boolean {
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
 * Whether one block has something of this run to draw.
 *
 * Exported for its own test: the answers below are the whole of the rule,
 * and each is a sentence about what the run produced rather than about what
 * the console can render.
 */
export function tabHasContent(
  key: string,
  report: ReportDetailDTO | null,
  roster?: JobRoster | null,
): boolean {
  if (ALWAYS.has(key)) return true;
  if (!report) return false;

  const mr = report.malware_report;
  const sections = mr?.sections;
  const placed = report.section_tabs;

  switch (key) {
    case "/identity":
      // The sample's own facts: the identity block, or a header table from
      // whichever binary-info tool ran.
      return Boolean(mr?.identity) || sectionsForTab(sections, "identity", placed).length > 0;
    case "/static":
      // The typed block, what a static tool returned, or the configuration
      // the analysis recovered, which is drawn on this tab and nowhere else
      // in full: a run with no static block still has it to show.
      return (
        Boolean(mr?.static) ||
        sectionsForTab(sections, "static", placed).length > 0 ||
        (mr?.technical_analysis?.configuration?.length ?? 0) > 0
      );
    case "/dynamic":
      // A sandbox report, what the ledger's sandbox tools returned, or the
      // dynamic analyst's own conclusion about a detonation that produced
      // nothing — a run where the analyst worked is not an empty run.
      return (
        Boolean(mr?.dynamic) ||
        sectionsForTab(sections, "dynamic", placed).length > 0 ||
        // The same reading the tab draws from, so the tab and its rule cannot
        // disagree about whether the analyst concluded anything.
        dynamicAnalystClaims(report.agent_findings, roster).length > 0
      );
    case "/network":
      // A capture or a sandbox network channel, and the endpoints carved out
      // of the binary's own strings when neither ran.
      return (
        Boolean(mr?.network) ||
        sectionsForTab(sections, "network", placed).length > 0 ||
        (mr?.static?.interesting_strings ?? []).some(
          (s) => s.kind === "domain" || s.kind === "ip" || s.kind === "url",
        )
      );
    case "/persistence":
      return nonEmpty(mr?.persistence) || sectionsForTab(sections, "persistence", placed).length > 0;
    case "/capabilities":
      /* The techniques the run named: the tab builds its matrix from the
       * capability matrix, which holds a cell for every one of them with the
       * reason beside any the run did not publish, and falls back to
       * `ttp_mappings` or to the `/mitre` endpoint whose stored copy is
       * `mitre_techniques` for a report stored before either.
       * `corroboration` is read per technique to decorate a card that already
       * exists, so a corroborated id the judge never mapped would offer a tab
       * that then apologises — which is the thing this rule is for.
       *
       * Asked through the parser the tab draws with rather than by counting
       * rows, so a list of rows that parses to no technique is not a mapping
       * here either. */
      return (
        hasMappedTechniques(mr?.capability_matrix) ||
        hasMappedTechniques(mr?.ttp_mappings) ||
        hasMappedTechniques(report.mitre_techniques)
      );
    case "/attribution":
      return attributionSaysSomething(mr);
    case "/detection":
      // Rules that fired, rules the run wrote, the indicators it recorded and
      // the STIX bundle it exports.
      return (
        // Not "a layer carried a claim" but "the panel has a row", which is
        // the same reading the panel itself makes.
        hasRuleMatches(report.agent_findings, sections) ||
        nonEmpty(mr?.detection_signatures) ||
        hasIndicators(mr) ||
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
