"use client";

import { useState } from "react";

interface YaraRule {
  match_count: number;
  rule_name: string;
  ruleset: string;
  source: string;
}

interface SigmaRule {
  severity: "critical" | "high" | "medium" | "low";
  rule_name: string;
  description: string;
  source: string;
}

const SEVERITY_STYLES: Record<string, { dots: string; text: string }> = {
  critical: { dots: "bg-status-red", text: "text-status-red" },
  high: { dots: "bg-status-orange", text: "text-status-orange" },
  medium: { dots: "bg-status-blue", text: "text-status-blue" },
  low: { dots: "bg-text-muted", text: "text-text-muted" },
};

const MOCK_YARA: YaraRule[] = [
  { match_count: 33, rule_name: "Emotet_Dropper_Gen", ruleset: "emotet_rules", source: "https://github.com/Neo23x0/signature-base" },
  { match_count: 16, rule_name: "Packed_PE_UPX_Modified", ruleset: "packer_detection", source: "https://github.com/elastic/protections-artifacts" },
  { match_count: 6, rule_name: "INDICATOR_SUSPICIOUS_EXE_References_VBNET", ruleset: "indicator_suspicious", source: "https://github.com/Neo23x0/signature-base" },
  { match_count: 5, rule_name: "MAL_Emotet_Banking_Trojan", ruleset: "emotet_banking", source: "https://github.com/volexity/threat-intel" },
  { match_count: 4, rule_name: "SUSP_XOR_Encoded_Strings", ruleset: "suspicious_encoding", source: "https://github.com/Neo23x0/signature-base" },
];

const MOCK_SIGMA: SigmaRule[] = [
  { severity: "critical", rule_name: "Suspicious Double Extension File Execution", description: "Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe", source: "Sigma Integrated Rule Set" },
  { severity: "critical", rule_name: "Process Injection via NtCreateSection", description: "Detects process injection using NtCreateSection API calls to map malicious code into remote processes", source: "Sigma Integrated Rule Set" },
  { severity: "high", rule_name: "Registry Run Key Persistence", description: "Detects creation of registry run keys commonly used for malware persistence mechanisms", source: "Sigma Integrated Rule Set" },
  { severity: "high", rule_name: "Outbound Connection to Known C2 IP", description: "Detects network connections to IP addresses associated with known command and control servers", source: "Sigma Integrated Rule Set" },
  { severity: "medium", rule_name: "Suspicious API Resolution Pattern", description: "Detects dynamic resolution of Windows API functions commonly used in malware", source: "Sigma Integrated Rule Set" },
];

function Section({
  title,
  defaultOpen,
  children,
}: {
  title: string;
  defaultOpen: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded mb-4">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-medium text-text-primary uppercase tracking-wider hover:bg-bg-hover transition-colors"
      >
        <span>{title}</span>
        <svg
          className={`w-4 h-4 text-text-muted transition-transform ${open ? "rotate-180" : ""}`}
          viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
        >
          <path d="m6 9 6 6 6-6" />
        </svg>
      </button>
      {open && <div className="border-t border-border">{children}</div>}
    </div>
  );
}

export default function RulesTab() {
  const severityCounts = MOCK_SIGMA.reduce(
    (acc, r) => {
      acc[r.severity] = (acc[r.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div>
      {/* YARA Rules */}
      <Section title="YARA Rules" defaultOpen={true}>
        <div className="bg-status-blue/10 px-4 py-2 border-b border-border">
          <span className="text-xs font-medium text-status-blue uppercase tracking-wider">
            YARA Rules
          </span>
        </div>
        <div className="divide-y divide-border-light">
          {MOCK_YARA.map((rule) => (
            <div
              key={rule.rule_name}
              className="flex items-center justify-between px-4 py-2.5 hover:bg-bg-hover transition-colors"
            >
              <div className="flex items-center gap-2 text-xs">
                <span className="text-accent">{rule.match_count} files</span>
                <span className="text-text-muted">match rule</span>
                <span className="text-accent">{rule.rule_name}</span>
                <span className="text-text-muted">from ruleset</span>
                <span className="text-accent">{rule.ruleset}</span>
                <span className="text-text-muted">at</span>
                <span className="text-text-secondary truncate max-w-xs">
                  {rule.source}
                </span>
              </div>
              <button className="text-text-muted hover:text-text-primary">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                  <circle cx="12" cy="5" r="1.5" />
                  <circle cx="12" cy="12" r="1.5" />
                  <circle cx="12" cy="19" r="1.5" />
                </svg>
              </button>
            </div>
          ))}
        </div>
      </Section>

      {/* Sigma Rules */}
      <Section title="Sigma Rules" defaultOpen={true}>
        <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-bg-elevated">
          <span className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Sigma Rules
          </span>
          <div className="flex items-center gap-3">
            {(["critical", "high", "medium", "low"] as const).map((sev) => (
              <label key={sev} className="flex items-center gap-1 text-xs text-text-secondary">
                <input
                  type="checkbox"
                  defaultChecked
                  className="w-3 h-3 accent-accent"
                />
                <span className="capitalize">{sev}</span>
                <span className="text-text-muted">({severityCounts[sev] || 0})</span>
              </label>
            ))}
          </div>
        </div>
        <div className="divide-y divide-border-light">
          {MOCK_SIGMA.map((rule) => {
            const style = SEVERITY_STYLES[rule.severity];
            return (
              <div
                key={rule.rule_name}
                className="flex items-start gap-3 px-4 py-3 hover:bg-bg-hover transition-colors"
              >
                <div className="flex items-center gap-1 mt-0.5 shrink-0 w-16">
                  <div className="flex gap-0.5">
                    {Array.from({
                      length: rule.severity === "critical" ? 4 : rule.severity === "high" ? 3 : rule.severity === "medium" ? 2 : 1,
                    }).map((_, i) => (
                      <span key={i} className={`w-1.5 h-1.5 rounded-full ${style.dots}`} />
                    ))}
                  </div>
                  <span className={`text-xs capitalize ml-1 ${style.text}`}>
                    {rule.severity}
                  </span>
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-accent">{rule.rule_name}</p>
                  <p className="text-xs text-text-secondary mt-0.5">
                    {rule.description}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </Section>
    </div>
  );
}
