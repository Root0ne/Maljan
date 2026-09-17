import { describe, expect, it } from "vitest";

import type { ReportDetailDTO } from "@/lib/api";
import type { EvidenceSection, MalwareReport } from "@/types/malware-report";
import { TABS, tabHasContent, tabsFor, hasRuleMatches } from "../analysisTabs";

function section(over: Partial<EvidenceSection> = {}): EvidenceSection {
  return {
    key: "sandbox_processes",
    title: "Sandbox processes",
    kind: "table",
    columns: ["PID", "Image"],
    rows: [["1234", "sample.exe"]],
    text: "",
    items: [],
    evidence_ids: ["ev_0004"],
    source: "tool:sandbox_processes",
    ...over,
  };
}

/** A report that produced nothing. Each test adds back exactly one fact. */
function malwareReport(over: Partial<MalwareReport> = {}): MalwareReport {
  return {
    schema_version: "1.0",
    generated_at: "2026-09-17T10:00:00Z",
    verdict: "Malware",
    overall_confidence: 0.8,
    malware_category: null,
    severity: null,
    identity: {
      hashes: {
        md5: null,
        sha1: null,
        sha256: "a".repeat(64),
        sha512: null,
        imphash: null,
        ssdeep: null,
        tlsh: null,
      },
      file_name: "sample.exe",
      file_size_bytes: 1024,
      file_type: "pe",
      platform: "windows",
      mime_type: null,
      magic_bytes: "MZ",
      compile_timestamp: null,
      language_or_compiler: null,
      signing: {
        is_signed: false,
        signer_subject: null,
        signer_issuer: null,
        signature_valid: null,
      },
    },
    static: null,
    dynamic: null,
    network: null,
    persistence: [],
    capability_matrix: [],
    ttp_mappings: [],
    attribution: {
      family: null,
      family_confidence: 0,
      family_grounded: true,
      actor: null,
      campaign: null,
      similar_samples: [],
    },
    executive_summary: "",
    capabilities_narrative: [],
    defensive_recommendations: [],
    detection_signatures: [],
    run_summary: {},
    negotiation_summary: {},
    stix_bundle_extended: {},
    misp_attributes: null,
    references: [],
    ...over,
  };
}

function report(over: Partial<ReportDetailDTO> = {}): ReportDetailDTO {
  return {
    id: "report-1",
    job_id: "job-1",
    verdict: "Malware",
    overall_confidence: 0.8,
    malware_category: null,
    stix_bundle: null,
    mitre_techniques: null,
    agent_reports: null,
    negotiation_log: null,
    run_summary: null,
    agent_findings: [],
    malware_report: malwareReport(),
    created_at: "2026-09-17T10:00:00Z",
    ...over,
  };
}

function keys(tabs: { key: string }[]): string[] {
  return tabs.map((t) => t.key);
}

describe("the tabs a run offers", () => {
  it("offers the three that answer before the run has produced anything", () => {
    expect(keys(tabsFor(null))).toEqual(["", "/conversation", "/evidence"]);
  });

  it("offers nothing a report with no findings cannot fill", () => {
    // The identity block is always present on a report, so IDENTITY joins the
    // three; everything else has to be earned.
    expect(keys(tabsFor(report()))).toEqual(["", "/conversation", "/identity", "/evidence"]);
  });

  it("offers every tab once the run has filled them", () => {
    const full = report({
      mitre_techniques: [{ technique_id: "T1055" }],
      stix_bundle: { type: "bundle", objects: [{}] },
      malware_report: malwareReport({
        static: {
          sections: [],
          imports: [],
          exports: [],
          interesting_strings: [],
          embedded_resources: [],
          packer_hint: null,
          obfuscation_indicators: [],
        },
        dynamic: {
          process_tree: [],
          registry_mods: [],
          file_operations: [],
          notable_apis: [],
          sandbox_signatures: [],
        },
        network: {
          domains: [],
          ips: [],
          urls: [],
          user_agents: [],
          ja3_fingerprints: [],
          ja3s_fingerprints: [],
        },
        persistence: [
          { kind: "registry_run", target: "Run", payload: "x", technique_id: null, evidence_ref: "ev_1" },
        ],
        ttp_mappings: [
          {
            technique_id: "T1055",
            technique_name: "Process Injection",
            tactic: "TA0004",
            evidence_quotes: [],
            confidence: 0.9,
            contributing_layers: [],
            is_corroborated: true,
          },
        ],
        attribution: {
          family: "FormBook",
          family_confidence: 0.7,
          family_grounded: true,
          actor: null,
          campaign: null,
          similar_samples: [],
        },
        defensive_recommendations: [
          {
            category: "firewall",
            action: "Block the C2",
            rationale: "It is the C2",
            priority: "P0",
            technique_id: null,
            detection: null,
          },
        ],
      }),
    });
    expect(keys(tabsFor(full))).toEqual(TABS.map((t) => t.key));
  });
});

describe("a tab earned by the ledger rather than by a typed block", () => {
  it("offers DYNAMIC for a sandbox section with no typed dynamic block", () => {
    const withSection = report({
      malware_report: malwareReport({ sections: [section()] }),
    });
    expect(tabHasContent("/dynamic", withSection)).toBe(true);
  });

  it("does not offer DYNAMIC for a sandbox section that returned nothing", () => {
    const empty = report({
      malware_report: malwareReport({ sections: [section({ rows: [] })] }),
    });
    expect(tabHasContent("/dynamic", empty)).toBe(false);
  });

  it("offers DYNAMIC when the analyst concluded something about a silent sandbox", () => {
    const analyst = report({
      agent_findings: [
        {
          agent_name: "dynamic",
          domain: "dynamic",
          claims: [{ claim: "The sample detected the sandbox and exited." }],
          dissent_items: null,
          revision_rounds: 1,
          final_confidence: 0.6,
        } as ReportDetailDTO["agent_findings"][number],
      ],
    });
    expect(tabHasContent("/dynamic", analyst)).toBe(true);
  });

  it("offers NETWORK for an endpoint carved out of the binary's own strings", () => {
    const strings = report({
      malware_report: malwareReport({
        static: {
          sections: [],
          imports: [],
          exports: [],
          interesting_strings: [{ value: "888kafa.com", kind: "domain", notes: null }],
          embedded_resources: [],
          packer_hint: null,
          obfuscation_indicators: [],
        },
      }),
    });
    expect(tabHasContent("/network", strings)).toBe(true);
    // The same report earns STATIC, because the typed static block is there.
    expect(tabHasContent("/static", strings)).toBe(true);
  });

  it("offers ATT&CK for corroboration alone, which is a mapping too", () => {
    const corroborated = report({
      run_summary: { corroboration: { T1055: { asserted_by: ["capa"], claimed_by: [] } } },
    });
    expect(tabHasContent("/capabilities", corroborated)).toBe(true);
  });

  it("does not offer ATTRIBUTION for an attribution block that named nothing", () => {
    expect(tabHasContent("/attribution", report())).toBe(false);
  });

  it("offers DETECTION for a rule that fired, with nothing generated", () => {
    const fired = report({
      agent_findings: [
        {
          agent_name: "yara_layer",
          domain: "static",
          claims: [{ claim: "Deterministic YARA signature match: sandbox_evasion" }],
          dissent_items: null,
          revision_rounds: 0,
          final_confidence: 1,
        } as ReportDetailDTO["agent_findings"][number],
      ],
    });
    expect(hasRuleMatches(fired)).toBe(true);
    expect(tabHasContent("/detection", fired)).toBe(true);
  });

  it("reads no rule matches from a report that is not there", () => {
    expect(hasRuleMatches(null)).toBe(false);
  });
});
