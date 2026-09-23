"use client";

import { useReport } from "../layout";
import RuleMatchesPanel from "@/components/analysis/RuleMatchesPanel";
import GeneratedRulesPanel from "@/components/analysis/GeneratedRulesPanel";
import StixPanel from "@/components/analysis/StixPanel";
import { hasRuleMatches } from "@/components/analysis/ruleMatches";

/**
 * Unified "Detection" tab.
 *
 * The two features that used to live in separate SIGNATURES and RULES tabs are
 * genuinely different things, and their old names implied the opposite of what
 * they showed. They are merged here under one tab with two clearly-labelled,
 * self-explanatory sections:
 *
 *   1. Rule matches from analysis  — YARA/Sigma rules that fired against the
 *      sample during this analysis (drives the ATT&CK techniques).
 *   2. Generated detection rules   — draft YARA/Sigma/Suricata rules Maljan
 *      produced for you to deploy to your own SOC tooling.
 */
export default function DetectionTab() {
  const { report } = useReport();
  const mr = report?.malware_report;
  const generated = mr?.detection_signatures ?? [];
  const matched = hasRuleMatches(report?.agent_findings, mr?.sections);
  // A bundle with no objects in it is a bundle nobody wants to export.
  const stix = Object.keys(mr?.stix_bundle_extended ?? report?.stix_bundle ?? {}).length > 0;

  return (
    <div className="space-y-6">
      {matched && (
        <section>
          <div className="mb-3">
            <h2 className="text-sm font-semibold text-text-primary">
              Rule matches from analysis
            </h2>
            <p className="text-xs text-text-muted mt-0.5">
              Deterministic YARA / Sigma rules that fired against this sample
              during analysis. These matches feed the ATT&amp;CK technique mapping.
            </p>
          </div>
          <RuleMatchesPanel />
        </section>
      )}

      {generated.length > 0 && (
        <section>
          <div className="mb-3 pt-4 border-t border-border">
            <h2 className="text-sm font-semibold text-text-primary">
              Generated detection rules
            </h2>
            <p className="text-xs text-text-muted mt-0.5">
              Draft YARA / Sigma / Suricata rules Maljan generated from this
              sample&apos;s IOCs — copy or download them into your own SOC tooling.
            </p>
          </div>
          <GeneratedRulesPanel />
        </section>
      )}

      {stix && (
        <section>
          <div className="mb-3 pt-4 border-t border-border">
            <h2 className="text-sm font-semibold text-text-primary">
              STIX 2.1 bundle (export)
            </h2>
            <p className="text-xs text-text-muted mt-0.5">
              Machine-readable STIX 2.1 bundle for sharing with other tooling —
              copy or download from the controls below.
            </p>
          </div>
          <StixPanel />
        </section>
      )}

      {!matched && generated.length === 0 && !stix && (
        <p className="p-8 text-center text-sm text-text-secondary">
          No rule fired on this sample, and the run wrote none of its own.
        </p>
      )}
    </div>
  );
}
