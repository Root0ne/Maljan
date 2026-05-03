"use client";

interface AgentResult {
  name: string;
  verdict: string;
  confidence: number;
  key_finding: string;
}

const MOCK_AGENTS: AgentResult[] = [
  { name: "Static Analyst", verdict: "malicious", confidence: 92, key_finding: "Packed PE with high entropy sections (.text: 7.94), UPX-modified headers" },
  { name: "Dynamic Analyst", verdict: "malicious", confidence: 88, key_finding: "Process injection via NtCreateSection into explorer.exe" },
  { name: "Network Analyst", verdict: "malicious", confidence: 85, key_finding: "HTTPS C2 beaconing to 185.x.x.x:443 with Emotet JA3 fingerprint" },
  { name: "Code Analyst", verdict: "suspicious", confidence: 72, key_finding: "Dynamic API resolution chains, obfuscated string decryption routines" },
  { name: "Threat Intel Analyst", verdict: "malicious", confidence: 91, key_finding: "SHA256 matches known Emotet dropper (first seen: 2026-04-28)" },
];

const VERDICT_STYLES: Record<string, { icon: string; class: string }> = {
  malicious: { icon: "\u2716", class: "text-status-red" },
  suspicious: { icon: "?", class: "text-status-orange" },
  benign: { icon: "\u2714", class: "text-status-green" },
  unknown: { icon: "-", class: "text-text-muted" },
};

export default function AgentsTab() {
  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          Agent Detection Results
        </h2>
        <span className="text-xs text-text-muted">
          {MOCK_AGENTS.filter((a) => a.verdict === "malicious").length}/{MOCK_AGENTS.length} flagged as malicious
        </span>
      </div>

      <table className="w-full">
        <thead>
          <tr className="border-b border-border">
            <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-44">Agent</th>
            <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-28">Verdict</th>
            <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider w-24">Confidence</th>
            <th className="text-left text-xs text-text-muted font-normal px-4 py-2 uppercase tracking-wider">Key Finding</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border-light">
          {MOCK_AGENTS.map((agent) => {
            const style = VERDICT_STYLES[agent.verdict] || VERDICT_STYLES.unknown;
            return (
              <tr key={agent.name} className="hover:bg-bg-hover transition-colors">
                <td className="px-4 py-3">
                  <span className="text-sm text-text-primary">{agent.name}</span>
                </td>
                <td className="px-4 py-3">
                  <div className={`flex items-center gap-1.5 ${style.class}`}>
                    <span className="text-sm">{style.icon}</span>
                    <span className="text-xs font-medium capitalize">{agent.verdict}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-12 h-1.5 bg-bg-deep rounded-sm overflow-hidden">
                      <div
                        className="h-full rounded-sm"
                        style={{
                          width: `${agent.confidence}%`,
                          backgroundColor: agent.confidence >= 80 ? "var(--status-red)" : agent.confidence >= 60 ? "var(--status-orange)" : "var(--status-green)",
                          opacity: 0.7,
                        }}
                      />
                    </div>
                    <span className="text-xs text-text-secondary font-mono">{agent.confidence}%</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span className="text-xs text-text-secondary">{agent.key_finding}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
