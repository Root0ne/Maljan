"use client";

import { useReport } from "./layout";

const VERDICT_COLORS: Record<string, string> = {
  malicious: "bg-status-red",
  suspicious: "bg-status-orange",
  benign: "bg-status-green",
  unknown: "bg-text-muted",
};

const VERDICT_TEXT: Record<string, string> = {
  malicious: "text-status-red",
  suspicious: "text-status-orange",
  benign: "text-status-green",
  unknown: "text-text-muted",
};

export default function SummaryTab() {
  const { report, job, loading } = useReport();

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  // If there's no report yet and job is still running/queued, show a loading or waiting state
  if (!report && (!job || job.status !== "completed")) {
    return (
      <div className="p-4 text-sm text-text-secondary animate-pulse">
        Analysis in progress... Gathering intelligence.
      </div>
    );
  }

  const agentSummary = report?.agent_findings?.map(f => {
    let verdict = "unknown";
    if (f.final_confidence >= 80) verdict = "malicious";
    else if (f.final_confidence >= 50) verdict = "suspicious";
    else verdict = "benign";

    return {
      name: f.agent_name,
      verdict: verdict,
      confidence: Math.round(f.final_confidence),
    };
  }) || [];

  let keyFindings: string[] = [];
  if (report?.agent_findings) {
    for (const finding of report.agent_findings) {
      if (finding.claims && Array.isArray(finding.claims)) {
        for (const claim of finding.claims) {
          if (claim && typeof claim === 'object' && 'description' in claim) {
             keyFindings.push(String((claim as any).description));
          } else if (typeof claim === 'string') {
             keyFindings.push(claim);
          }
        }
      }
    }
  }

  if (keyFindings.length === 0 && report?.mitre_techniques) {
    keyFindings = report.mitre_techniques.map((t: any) => t.name || t.technique_id || "Unknown technique");
  }

  keyFindings = Array.from(new Set(keyFindings)).slice(0, 6);
  if (keyFindings.length === 0) {
    keyFindings = ["No specific findings were extracted."];
  }

  const verdictLabel = report?.verdict ? report.verdict.charAt(0).toUpperCase() + report.verdict.slice(1) : "Unknown";
  const confidence = report?.overall_confidence ? Math.round(report.overall_confidence) : 0;
  const verdictColorClass = VERDICT_TEXT[report?.verdict?.toLowerCase() || 'unknown'] || VERDICT_TEXT.unknown;

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
          {agentSummary.length > 0 ? agentSummary.map((a) => (
            <div key={a.name} className="flex items-center gap-3">
              <span className="text-xs text-text-secondary w-32 shrink-0 truncate">
                {a.name}
              </span>
              <div className="flex-1 h-2 bg-bg-deep rounded-sm overflow-hidden">
                <div
                  className={`h-full rounded-sm ${VERDICT_COLORS[a.verdict] || VERDICT_COLORS.unknown}`}
                  style={{ width: `${a.confidence}%`, opacity: 0.7 }}
                />
              </div>
              <span className={`text-xs font-mono w-8 text-right ${VERDICT_TEXT[a.verdict] || VERDICT_TEXT.unknown}`}>
                {a.confidence}
              </span>
            </div>
          )) : (
            <div className="text-sm text-text-secondary">No agent data available.</div>
          )}
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
            {keyFindings.map((f, i) => (
              <li key={i} className="flex gap-2 text-xs text-text-secondary">
                <span className="text-status-red mt-0.5 shrink-0">-</span>
                <span className="truncate" title={f}>{f}</span>
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
            The analyzed sample has been classified as{" "}
            <strong className={verdictColorClass}>{verdictLabel}</strong> with a consensus
            confidence score of <strong>{confidence}/100</strong>.
            {report?.malware_category ? ` Detected malware category: ${report.malware_category}.` : ""}
            {agentSummary.length > 0 ? ` The analysis involved ${agentSummary.length} agent(s).` : ""}
            {!report ? " Analysis is currently incomplete or data is missing." : ""}
          </p>
        </div>
      </div>
    </div>
  );
}
