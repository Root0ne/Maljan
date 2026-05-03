"use client";

const AGENTS_SUMMARY = [
  { name: "Static Analyst", verdict: "malicious", confidence: 92 },
  { name: "Dynamic Analyst", verdict: "malicious", confidence: 88 },
  { name: "Network Analyst", verdict: "malicious", confidence: 85 },
  { name: "Code Analyst", verdict: "suspicious", confidence: 72 },
  { name: "Threat Intel Analyst", verdict: "malicious", confidence: 91 },
];

const KEY_FINDINGS = [
  "High-entropy packed PE executable with anti-analysis techniques",
  "Dynamic API resolution using GetProcAddress chains",
  "C2 communication with known Emotet infrastructure (185.x.x.x)",
  "Registry persistence via HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "Process injection into explorer.exe using NtCreateSection",
  "Matches YARA rule: Emotet_Dropper_Gen (Florian Roth)",
];

const VERDICT_COLORS: Record<string, string> = {
  malicious: "bg-status-red",
  suspicious: "bg-status-orange",
  benign: "bg-status-green",
};

const VERDICT_TEXT: Record<string, string> = {
  malicious: "text-status-red",
  suspicious: "text-status-orange",
  benign: "text-status-green",
};

export default function SummaryTab() {
  return (
    <div className="grid grid-cols-2 gap-4">
      {/* Agent Confidence Overview */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Agent Consensus
          </h2>
        </div>
        <div className="p-4 space-y-3">
          {AGENTS_SUMMARY.map((a) => (
            <div key={a.name} className="flex items-center gap-3">
              <span className="text-xs text-text-secondary w-32 shrink-0 truncate">
                {a.name}
              </span>
              <div className="flex-1 h-2 bg-bg-deep rounded-sm overflow-hidden">
                <div
                  className={`h-full rounded-sm ${VERDICT_COLORS[a.verdict]}`}
                  style={{ width: `${a.confidence}%`, opacity: 0.7 }}
                />
              </div>
              <span className={`text-xs font-mono w-8 text-right ${VERDICT_TEXT[a.verdict]}`}>
                {a.confidence}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Key Findings */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Key Findings
          </h2>
        </div>
        <div className="p-4">
          <ul className="space-y-2">
            {KEY_FINDINGS.map((f, i) => (
              <li key={i} className="flex gap-2 text-xs text-text-secondary">
                <span className="text-status-red mt-0.5 shrink-0">-</span>
                <span>{f}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Executive Summary */}
      <div className="col-span-2 bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Executive Summary
          </h2>
        </div>
        <div className="p-4">
          <p className="text-sm text-text-secondary leading-relaxed">
            The submitted sample (emotet_dropper.exe) has been classified as{" "}
            <strong className="text-status-red">Malicious</strong> with a consensus
            confidence score of 87/100. All five agents concur on the malicious
            nature of this executable. Static analysis reveals a packed PE binary
            employing anti-analysis evasion. Dynamic analysis confirms process
            injection into explorer.exe and persistent C2 communication with known
            Emotet botnet infrastructure. The sample matches established YARA
            signatures and exhibits MITRE ATT&CK techniques spanning Initial Access,
            Execution, Persistence, Defense Evasion, and Command and Control tactics.
          </p>
        </div>
      </div>
    </div>
  );
}
