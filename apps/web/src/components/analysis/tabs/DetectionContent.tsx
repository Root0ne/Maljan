"use client";

import { useReport } from "@/components/analysis/AnalysisContext";
import Section from "@/components/ui/Section";
import RuleMatchesPanel from "@/components/analysis/RuleMatchesPanel";
import GeneratedRulesPanel from "@/components/analysis/GeneratedRulesPanel";
import StixPanel from "@/components/analysis/StixPanel";
import IocBrowser from "@/components/analysis/IocBrowser";
import { hasRuleMatches } from "@/components/analysis/ruleMatches";

/**
 * Indicators and detection, in the order a reader acts on them: every
 * indicator, browsable by type and export decision, each with its reason and
 * what else the report says about it; the rules that fired against the
 * sample during the analysis; the rules the analysis wrote for a reader to
 * deploy, one list with a copy and a download per rule; and the STIX bundle
 * the export is made of, drawn on request.
 */
export default function DetectionContent() {
  const { report } = useReport();
  const mr = report?.malware_report;
  const generated = mr?.detection_signatures ?? [];
  const matched = hasRuleMatches(report?.agent_findings, mr?.sections);
  // A bundle with no objects in it is a bundle nobody wants to export.
  const stix = Object.keys(mr?.stix_bundle_extended ?? report?.stix_bundle ?? {}).length > 0;

  return (
    <div className="space-y-4">
      <div id="iocs" className="scroll-mt-40">
        <IocBrowser mr={mr} />
      </div>

      <div id="rule-matches" className="scroll-mt-40">
        <Section title="Rules that fired" empty={!matched}>
          <div className="space-y-3">
            <p className="text-xs text-text-muted">
              Deterministic YARA and Sigma rules that fired against this sample during analysis. These matches feed
              the ATT&amp;CK technique mapping.
            </p>
            <RuleMatchesPanel />
          </div>
        </Section>
      </div>

      <div id="generated-rules" className="scroll-mt-40">
        <Section title="Generated detection rules" count={generated.length || null} empty={generated.length === 0}>
          <div className="space-y-3">
            <p className="text-xs text-text-muted">
              Draft YARA, Sigma and Suricata rules generated from this sample&apos;s indicators, for your own
              detection tooling.
            </p>
            <GeneratedRulesPanel />
          </div>
        </Section>
      </div>

      <div id="stix" className="scroll-mt-40">
        <Section title="STIX 2.1 objects" empty={!stix} collapsible defaultOpen={false}>
          <div className="space-y-3">
            <p className="text-xs text-text-muted">
              The machine-readable bundle the export shares with other tooling, drawn as a relationship graph,
              listed as a table, or shown as JSON to copy; the bundle itself downloads from Export at the top of the
              page.
            </p>
            <StixPanel />
          </div>
        </Section>
      </div>
    </div>
  );
}
