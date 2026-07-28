import type { ReportDetailDTO } from "@/lib/api";
import type { MalwareReport } from "@/types/malware-report";

/**
 * One complete report, typed against the real DTO.
 *
 * The analysis view is twelve tabs over one payload, so a per-spec inline
 * fixture would drift from the schema the moment a field moved. Typing this as
 * `ReportDetailDTO` makes `tsc` the thing that keeps them aligned: a backend
 * field that changes shape breaks the build here rather than producing a green
 * test against a payload the API no longer sends.
 *
 * Every slice carries exactly one realistic item, which is what each tab needs
 * to render its populated branch rather than its empty state — the two look
 * very similar from a test's point of view, and only the populated branch
 * proves anything. Two details are load-bearing rather than decorative:
 *
 *  - `agent_findings` uses the literal names `yara_layer` and `sigma_layer`,
 *    which is what the detection panel keys off (RuleMatchesPanel.tsx).
 *  - `ttp_mappings` is non-empty, which both populates the ATT&CK tab and
 *    suppresses its fallback call to `/reports/{id}/mitre`.
 *
 * The Summary tab is the fragile consumer: it dereferences `severity.rating`,
 * `identity.hashes.sha256`, `attribution.family`, `capabilities_narrative` and
 * `stix_bundle_extended` with no guards, and there is no error boundary in the
 * app, so a missing one takes the page down rather than degrading.
 */

export const JOB_ID = "11111111-2222-3333-4444-555555555555";
export const REPORT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
export const SAMPLE_ID = "99999999-8888-7777-6666-555555555555";
export const SAMPLE_SHA256 =
  "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

export const MALWARE_REPORT: MalwareReport = {
  schema_version: "1.0",
  generated_at: "2026-07-26T12:30:00Z",
  verdict: "Malware",
  overall_confidence: 0.91,
  malware_category: "trojan",
  severity: {
    overall_score: 8.4,
    rating: "High",
    business_impact: "Credential theft followed by lateral movement.",
    affected_platforms: ["windows"],
    likely_targets: ["Finance staff"],
  },
  identity: {
    hashes: {
      md5: "5d41402abc4b2a76b9719d911017c592",
      sha1: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
      sha256: SAMPLE_SHA256,
      sha512: null,
      imphash: "b9f8a1c4d3e2f10987654321abcdef01",
      ssdeep: null,
      tlsh: null,
    },
    file_name: "invoice_scan.exe",
    file_size_bytes: 204800,
    file_type: "PE32 executable",
    platform: "windows",
    mime_type: "application/x-dosexec",
    magic_bytes: "4d5a90000300000004000000ffff0000",
    compile_timestamp: "2026-07-20T08:15:00Z",
    language_or_compiler: "Microsoft Visual C/C++",
    signing: {
      is_signed: false,
      signer_subject: null,
      signer_issuer: null,
      signature_valid: null,
    },
  },
  static: {
    sections: [
      {
        name: ".text",
        virtual_address: "0x1000",
        virtual_size: 90112,
        raw_size: 90112,
        entropy: 7.82,
        characteristics: "CODE|EXECUTE|READ",
        is_suspicious: true,
      },
    ],
    imports: [
      {
        dll: "KERNEL32.dll",
        function: "VirtualAllocEx",
        is_suspicious: true,
        category: "process_injection",
      },
    ],
    exports: [],
    interesting_strings: [
      { value: "cdn.example-update.net", kind: "domain", notes: "C2 candidate" },
      { value: "185.199.110.153", kind: "ip", notes: null },
    ],
    embedded_resources: [],
    packer_hint: "UPX (modified)",
    obfuscation_indicators: ["High-entropy .text section"],
  },
  dynamic: {
    process_tree: [
      {
        pid: 1024,
        ppid: 640,
        name: "invoice_scan.exe",
        command_line: "invoice_scan.exe /silent",
        children: [
          {
            pid: 1180,
            ppid: 1024,
            name: "cmd.exe",
            command_line: "cmd.exe /c whoami",
            children: [],
            injected_into: [],
          },
        ],
        injected_into: [640],
      },
    ],
    registry_mods: [
      {
        hive: "HKCU",
        key: "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        value_name: "UpdateSvc",
        operation: "create",
        new_value: "C:\\Users\\Public\\svc.exe",
      },
    ],
    file_operations: [],
    notable_apis: [],
    sandbox_signatures: [
      {
        name: "process_injection",
        description: "Writes into another process's address space",
        severity: 8,
        technique_ids: ["T1055"],
        marks: ["WriteProcessMemory into pid 640"],
      },
    ],
  },
  network: {
    domains: [
      {
        fqdn: "cdn.example-update.net",
        queried_pids: [1024],
        resolved_ips: ["185.199.110.153"],
        is_suspicious: true,
        reason: "Newly registered domain",
        dga_score: 0.12,
        is_punycode: false,
        homograph_target: null,
        reputation: null,
      },
    ],
    ips: [
      {
        address: "185.199.110.153",
        port: 443,
        transport: "tcp",
        asn: "AS54113",
        geo: "NL",
        is_suspicious: true,
        reputation: null,
      },
    ],
    urls: [
      {
        url: "https://cdn.example-update.net/gate.php",
        method: "POST",
        status: 200,
        user_agent: "Mozilla/5.0",
      },
    ],
    user_agents: ["Mozilla/5.0"],
    ja3_fingerprints: ["e7d705a3286e19ea42f587b344ee6865"],
    ja3s_fingerprints: [],
  },
  persistence: [
    {
      kind: "registry_run",
      target: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\UpdateSvc",
      payload: "C:\\Users\\Public\\svc.exe",
      technique_id: "T1547.001",
      evidence_ref: "registry_mods[0]",
    },
  ],
  capability_matrix: [
    {
      tactic: "TA0005",
      tactic_name: "Defense Evasion",
      technique_id: "T1055",
      technique_name: "Process Injection",
      evidence: ["WriteProcessMemory into pid 640"],
      confidence: 0.9,
      contributing_layers: ["static", "dynamic"],
    },
  ],
  ttp_mappings: [
    {
      technique_id: "T1055",
      technique_name: "Process Injection",
      tactic: "TA0005",
      tactic_name: "Defense Evasion",
      evidence_quotes: ["Imports VirtualAllocEx and WriteProcessMemory"],
      confidence: 0.9,
      contributing_layers: ["static", "dynamic"],
      is_corroborated: true,
    },
  ],
  attribution: {
    family: "AgentTesla",
    family_confidence: 0.72,
    family_grounded: true,
    actor: null,
    campaign: null,
    similar_samples: [],
    // The static byte markers that named the family. Present in the fixture
    // because this is the attribution path that survives an unreachable
    // sandbox, and it rendered in the markdown report while being invisible in
    // the UI until 2026-07-28.
    tool_artifact_matches: [
      {
        tool: "AsyncRAT",
        family: "AgentTesla",
        kind: "rat",
        confidence: 0.71,
        markers: ["Pastebin_URL", "AsyncRAT_Config"],
      },
    ],
  },
  executive_summary:
    "The sample injects into a running process, establishes Run-key persistence and beacons to a newly registered domain over HTTPS.",
  capabilities_narrative: [
    "Allocates and writes executable memory into an unrelated process.",
    "Registers itself for execution at user logon.",
  ],
  defensive_recommendations: [
    {
      category: "edr_hunting",
      action: "Hunt for WriteProcessMemory into non-child processes.",
      rationale: "The injection is the sample's first observable action.",
      priority: "P0",
      technique_id: "T1055",
      detection: "Sysmon Event ID 8",
    },
  ],
  detection_signatures: [
    {
      kind: "yara",
      name: "Maljan_AgentTesla_Injection",
      body: 'rule Maljan_AgentTesla_Injection { strings: $a = "VirtualAllocEx" condition: $a }',
      auto_generated: true,
      source_evidence: ["imports[0]"],
      compile_error: null,
    },
  ],
  run_summary: {
    degraded_mode: false,
    degradation_reasons: [],
    failed_analysts: [],
    cascade: null,
    fp_warnings: [],
  },
  negotiation_summary: { rounds: 1, consensus: false },
  stix_bundle_extended: { type: "bundle", id: "bundle--extended", objects: [] },
  misp_attributes: [],
  references: [
    {
      source: "MITRE ATT&CK",
      url: "https://attack.mitre.org/techniques/T1055/",
      note: null,
    },
  ],
};

/**
 * The recorded conversation — the same messages the live viewer saw.
 *
 * Two rounds, so the fixture actually exercises what the recording exists for:
 * the round-0 positions *and* the round-1 revisions, which the legacy rebuild
 * from `agent_findings` cannot produce (it only ever had each agent's final
 * position). The sycophancy notice is here for the same reason — it was
 * emitted live and persisted nowhere, so nothing could render it after a run.
 */
export const TRANSCRIPT = [
  {
    seq: 0,
    speaker: "static",
    role: "analyst",
    round: 0,
    status: "complete",
    text: "1 evidence-backed claim from the static layer. Leading: Imports VirtualAllocEx and WriteProcessMemory",
    report:
      "STATIC ANALYSIS\n\nThe .text section has an entropy of 7.82, consistent with packing. The import table resolves VirtualAllocEx and WriteProcessMemory, which together are the standard remote-injection pair.",
    report_truncated: false,
    confidence: 0.9,
    claims: [
      {
        claim: "Imports VirtualAllocEx and WriteProcessMemory",
        evidence_ref: "IAT: KERNEL32.dll!VirtualAllocEx",
        confidence: 0.9,
        technique_id: "T1055",
      },
    ],
    dissent: [],
    ts: "2026-07-26T12:04:00Z",
  },
  {
    seq: 1,
    speaker: "dynamic",
    role: "analyst",
    round: 0,
    status: "failed",
    text: "sandbox unreachable",
    report: null,
    report_truncated: false,
    confidence: null,
    claims: [],
    dissent: [],
    ts: "2026-07-26T12:04:30Z",
  },
  {
    seq: 2,
    speaker: "Mediator",
    role: "negotiator",
    round: 1,
    status: "complete",
    text: "Static evidence is uncorroborated by the dynamic layer.",
    report: null,
    report_truncated: false,
    confidence: 0.55,
    claims: [],
    dissent: [],
    ts: "2026-07-26T12:05:00Z",
  },
  {
    seq: 3,
    speaker: "Sycophancy detector",
    role: "system",
    round: 1,
    status: "complete",
    text:
      "Agents converged without new evidence — flagged as sycophantic agreement. " +
      "The next revision round carries a directive to re-argue from evidence rather than defer to peers.",
    report: null,
    report_truncated: false,
    confidence: null,
    claims: [],
    dissent: [],
    ts: "2026-07-26T12:05:10Z",
  },
  {
    seq: 4,
    speaker: "static",
    role: "reviser",
    round: 1,
    status: "complete",
    text: "1 evidence-backed claim from the static layer. Leading: Injection pair confirmed against the packed section",
    report:
      "STATIC ANALYSIS (revised)\n\nI stand by the injection finding. The dynamic layer produced no data at all rather than contradicting evidence, so its silence is not a counter-argument.",
    report_truncated: false,
    confidence: 0.88,
    claims: [
      {
        claim: "Injection pair confirmed against the packed section",
        evidence_ref: "IAT + .text entropy 7.82",
        confidence: 0.88,
        technique_id: "T1055",
      },
    ],
    dissent: ["Dynamic analyst reported no data; absence is not contradiction."],
    ts: "2026-07-26T12:08:00Z",
  },
  {
    seq: 5,
    speaker: "Judge",
    role: "judge",
    round: 1,
    status: "complete",
    text: "Final verdict: Malicious. Closed without full consensus — see the mediator rounds above.",
    report: null,
    report_truncated: false,
    confidence: 0.91,
    claims: [],
    dissent: [],
    ts: "2026-07-26T12:30:00Z",
  },
];

export const REPORT: ReportDetailDTO = {
  id: REPORT_ID,
  job_id: JOB_ID,
  // Raw backend spelling on purpose: every user-facing surface must normalise
  // this to "Malicious", and asserting on the raw value is the regression.
  verdict: "Malware",
  overall_confidence: 0.91,
  malware_category: "trojan",
  stix_bundle: {
    type: "bundle",
    id: "bundle--11111111-2222-3333-4444-555555555555",
    objects: [{ type: "indicator", id: "indicator--1", name: "C2 domain" }],
  },
  mitre_techniques: [{ technique_id: "T1055", name: "Process Injection" }],
  agent_reports: {
    static: "STATIC ANALYSIS (revised)\n\nI stand by the injection finding.",
    dynamic: "[ERROR] dynamic: sandbox unreachable",
  },
  negotiation_log: {
    discussion_history: [
      {
        round: 1,
        agent: "Mediator",
        argument: "Static evidence is uncorroborated by the dynamic layer.",
        confidence: 55,
      },
    ],
    is_consensus: false,
    iteration_count: 1,
  },
  run_summary: MALWARE_REPORT.run_summary,
  agent_findings: [
    {
      agent_name: "static",
      domain: "static",
      claims: [
        {
          claim: "Imports VirtualAllocEx and WriteProcessMemory",
          evidence_ref: "IAT: KERNEL32.dll!VirtualAllocEx",
          confidence: 0.9,
          technique_id: "T1055",
        },
      ],
      dissent_items: [],
      revision_rounds: 0,
      final_confidence: 0.9,
      status: "complete",
      status_reason: null,
    },
    {
      agent_name: "dynamic",
      domain: "dynamic",
      claims: [],
      dissent_items: [],
      revision_rounds: 0,
      final_confidence: 0,
      status: "failed",
      status_reason: "sandbox unreachable",
    },
    // These two names are not cosmetic: RuleMatchesPanel selects findings by
    // exactly these agent names to populate the detection tab.
    {
      agent_name: "yara_layer",
      domain: "detection",
      claims: [
        {
          claim: "YARA rule APT_Injection_Generic matched",
          evidence_ref: "rule: APT_Injection_Generic",
          confidence: 0.8,
          technique_id: "T1055",
        },
      ],
      dissent_items: [],
      revision_rounds: 0,
      final_confidence: 0.8,
      status: "complete",
      status_reason: null,
    },
    {
      agent_name: "sigma_layer",
      domain: "detection",
      claims: [
        {
          claim: "Sigma rule win_susp_run_key_persistence matched",
          evidence_ref: "rule: win_susp_run_key_persistence",
          confidence: 0.75,
          technique_id: "T1547.001",
        },
      ],
      dissent_items: [],
      revision_rounds: 0,
      final_confidence: 0.75,
      status: "complete",
      status_reason: null,
    },
  ],
  malware_report: MALWARE_REPORT,
  transcript: TRANSCRIPT,
  created_at: "2026-07-26T12:30:00Z",
};

/** The job the report belongs to, in its terminal state. */
export const COMPLETED_JOB = {
  id: JOB_ID,
  sample_id: SAMPLE_ID,
  sample_filename: "invoice_scan.exe",
  status: "completed",
  verdict: "Malware",
  config: null,
  created_at: "2026-07-26T12:00:00Z",
  started_at: "2026-07-26T12:00:05Z",
  completed_at: "2026-07-26T12:30:00Z",
  duration_seconds: 1795,
  error_message: null,
};
