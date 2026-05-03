"use client";

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  Legend,
} from "recharts";

interface Round {
  round: number;
  agent: string;
  position: string;
  confidence: number;
  argument: string;
}

const MOCK_ROUNDS: Round[] = [
  { round: 1, agent: "Static Analyst", position: "malicious", confidence: 85, argument: "High-entropy packed PE executable with UPX-modified headers and anti-debugging checks. Import table is minimal suggesting dynamic API resolution." },
  { round: 1, agent: "Dynamic Analyst", position: "malicious", confidence: 80, argument: "Sample creates a child process and injects code into explorer.exe via NtCreateSection. Modifies registry run keys for persistence." },
  { round: 1, agent: "Network Analyst", position: "suspicious", confidence: 65, argument: "Outbound HTTPS connections to 185.x.x.x:443 detected. JA3 fingerprint matches known Emotet patterns but could be coincidental." },
  { round: 1, agent: "Code Analyst", position: "suspicious", confidence: 60, argument: "Obfuscated string decryption routines found. Dynamic API resolution via GetProcAddress chains but this pattern is also used in legitimate packers." },
  { round: 1, agent: "Threat Intel Analyst", position: "malicious", confidence: 88, argument: "SHA256 hash matches known Emotet dropper first seen 2026-04-28. Associated C2 IPs are active in current Emotet campaign." },
  { round: 2, agent: "Network Analyst", position: "malicious", confidence: 82, argument: "After reviewing Threat Intel data, the C2 IP matches active Emotet infrastructure. JA3 fingerprint match is not coincidental given the full context." },
  { round: 2, agent: "Code Analyst", position: "malicious", confidence: 72, argument: "Correlating with dynamic analysis findings, the API resolution patterns are consistent with Emotet's loader. String decryption yields C2 URLs." },
  { round: 2, agent: "Static Analyst", position: "malicious", confidence: 92, argument: "Cross-referencing with YARA matches confirms Emotet_Dropper_Gen signature. Entropy profile matches known Emotet packing methodology." },
  { round: 2, agent: "Dynamic Analyst", position: "malicious", confidence: 88, argument: "Process injection target and technique match documented Emotet behavior. Registry persistence key format is identical to previous campaigns." },
  { round: 2, agent: "Threat Intel Analyst", position: "malicious", confidence: 91, argument: "All behavioral indicators align with Epoch 4 Emotet activity. High confidence classification as Emotet banking trojan dropper." },
];

const AGENT_COLORS: Record<string, string> = {
  "Static Analyst": "#4493f8",
  "Dynamic Analyst": "#f85149",
  "Network Analyst": "#d29922",
  "Code Analyst": "#3fb950",
  "Threat Intel Analyst": "#bc8cff",
};

const POSITION_STYLES: Record<string, string> = {
  malicious: "text-status-red",
  suspicious: "text-status-orange",
  benign: "text-status-green",
};

export default function TimelineTab() {
  /* Build chart data: per round, each agent's confidence */
  const rounds = [...new Set(MOCK_ROUNDS.map((r) => r.round))];
  const agents = [...new Set(MOCK_ROUNDS.map((r) => r.agent))];
  const chartData = rounds.map((round) => {
    const entry: Record<string, number> = { round };
    for (const a of agents) {
      const r = MOCK_ROUNDS.find((x) => x.round === round && x.agent === a);
      if (r) entry[a] = r.confidence;
    }
    return entry;
  });

  return (
    <div className="space-y-4">
      {/* Confidence Convergence Chart */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Confidence Convergence
          </h2>
        </div>
        <div className="p-4">
          <ResponsiveContainer width="100%" height={240}>
            <LineChart data={chartData}>
              <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" />
              <XAxis
                dataKey="round"
                tick={{ fill: "var(--text-muted)", fontSize: 11 }}
                axisLine={{ stroke: "var(--border)" }}
                tickLine={false}
                label={{
                  value: "Round",
                  position: "insideBottomRight",
                  offset: -5,
                  fill: "var(--text-muted)",
                  fontSize: 11,
                }}
              />
              <YAxis
                domain={[0, 100]}
                tick={{ fill: "var(--text-muted)", fontSize: 11 }}
                axisLine={{ stroke: "var(--border)" }}
                tickLine={false}
                label={{
                  value: "Confidence %",
                  angle: -90,
                  position: "insideLeft",
                  fill: "var(--text-muted)",
                  fontSize: 11,
                }}
              />
              <Tooltip
                contentStyle={{
                  background: "var(--bg-elevated)",
                  border: "1px solid var(--border)",
                  borderRadius: "4px",
                  fontSize: "11px",
                  color: "var(--text-primary)",
                }}
              />
              <Legend
                wrapperStyle={{ fontSize: "11px" }}
                formatter={(value: string) => (
                  <span style={{ color: "var(--text-secondary)" }}>{value}</span>
                )}
              />
              {agents.map((agent) => (
                <Line
                  key={agent}
                  type="monotone"
                  dataKey={agent}
                  stroke={AGENT_COLORS[agent]}
                  strokeWidth={1.5}
                  dot={{ fill: AGENT_COLORS[agent], r: 3 }}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Debate Timeline */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Negotiation Debate
          </h2>
        </div>
        <div className="divide-y divide-border-light">
          {MOCK_ROUNDS.map((entry, i) => (
            <div key={i} className="flex gap-4 px-4 py-3 hover:bg-bg-hover transition-colors">
              <div className="flex flex-col items-center shrink-0 w-12">
                <span className="text-xs text-text-muted">R{entry.round}</span>
                <div
                  className="w-2 h-2 rounded-full mt-1"
                  style={{ backgroundColor: AGENT_COLORS[entry.agent] }}
                />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className="text-xs font-medium"
                    style={{ color: AGENT_COLORS[entry.agent] }}
                  >
                    {entry.agent}
                  </span>
                  <span className={`text-xs capitalize ${POSITION_STYLES[entry.position] || "text-text-muted"}`}>
                    {entry.position}
                  </span>
                  <span className="text-xs text-text-muted font-mono">
                    {entry.confidence}%
                  </span>
                </div>
                <p className="text-xs text-text-secondary leading-relaxed">
                  {entry.argument}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
