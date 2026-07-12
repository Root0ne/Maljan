"use client";

import RuleMatchesPanel from "../rules/page";
import GeneratedRulesPanel from "../signatures/page";

/**
 * Unified "Detection" tab (2026-07 audit, Bulgu #1 UI).
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
  return (
    <div className="space-y-6">
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
    </div>
  );
}
