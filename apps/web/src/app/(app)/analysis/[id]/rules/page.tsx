"use client";

import { useState } from "react";
import { useReport } from "../layout";

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
  const { report, job, loading } = useReport();

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  if (!report && (!job || job.status !== "completed")) {
    return (
      <div className="p-4 text-sm text-text-secondary animate-pulse">
        Analysis in progress...
      </div>
    );
  }

  // Extract YARA and Sigma rules from run_summary JSONB field
  const runSummary = report?.run_summary as Record<string, unknown> | null | undefined;

  const yaraRules: YaraRule[] = [];
  const sigmaRules: SigmaRule[] = [];

  if (runSummary) {
    // Try yara_matches / yara_results
    const yaraRaw =
      (runSummary.yara_matches as unknown[]) ||
      (runSummary.yara_results as unknown[]) ||
      [];
    for (const item of yaraRaw) {
      if (item && typeof item === "object") {
        const r = item as Record<string, unknown>;
        yaraRules.push({
          match_count: Number(r.match_count ?? r.matches ?? 1),
          rule_name: String(r.rule_name ?? r.name ?? "Unknown"),
          ruleset: String(r.ruleset ?? r.namespace ?? ""),
          source: String(r.source ?? r.url ?? ""),
        });
      }
    }

    // Try sigma_matches / sigma_results
    const sigmaRaw =
      (runSummary.sigma_matches as unknown[]) ||
      (runSummary.sigma_results as unknown[]) ||
      [];
    for (const item of sigmaRaw) {
      if (item && typeof item === "object") {
        const r = item as Record<string, unknown>;
        const sev = String(r.severity ?? r.level ?? "medium").toLowerCase() as SigmaRule["severity"];
        sigmaRules.push({
          severity: (["critical", "high", "medium", "low"] as const).includes(sev as never) ? sev : "medium",
          rule_name: String(r.rule_name ?? r.name ?? "Unknown"),
          description: String(r.description ?? r.title ?? ""),
          source: String(r.source ?? ""),
        });
      }
    }
  }

  const severityCounts = sigmaRules.reduce(
    (acc, r) => {
      acc[r.severity] = (acc[r.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const hasData = yaraRules.length > 0 || sigmaRules.length > 0;

  if (!hasData) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        {report
          ? "No YARA or Sigma rule matches were recorded for this analysis."
          : "Analysis has not completed yet."}
      </div>
    );
  }

  return (
    <div>
      {/* YARA Rules */}
      {yaraRules.length > 0 && (
        <Section title={`YARA Rules (${yaraRules.length})`} defaultOpen={true}>
          <div className="bg-status-blue/10 px-4 py-2 border-b border-border">
            <span className="text-xs font-medium text-status-blue uppercase tracking-wider">
              YARA Rules
            </span>
          </div>
          <div className="divide-y divide-border-light">
            {yaraRules.map((rule) => (
              <div
                key={rule.rule_name}
                className="flex items-center justify-between px-4 py-2.5 hover:bg-bg-hover transition-colors"
              >
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-accent">{rule.match_count} files</span>
                  <span className="text-text-muted">match rule</span>
                  <span className="text-accent">{rule.rule_name}</span>
                  {rule.ruleset && (
                    <>
                      <span className="text-text-muted">from ruleset</span>
                      <span className="text-accent">{rule.ruleset}</span>
                    </>
                  )}
                  {rule.source && (
                    <>
                      <span className="text-text-muted">at</span>
                      <span className="text-text-secondary truncate max-w-xs">{rule.source}</span>
                    </>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Sigma Rules */}
      {sigmaRules.length > 0 && (
        <Section title={`Sigma Rules (${sigmaRules.length})`} defaultOpen={true}>
          <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-bg-elevated">
            <span className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Sigma Rules
            </span>
            <div className="flex items-center gap-3">
              {(["critical", "high", "medium", "low"] as const).map((sev) => (
                <span key={sev} className="flex items-center gap-1 text-xs text-text-secondary">
                  <span className="capitalize">{sev}</span>
                  <span className="text-text-muted">({severityCounts[sev] || 0})</span>
                </span>
              ))}
            </div>
          </div>
          <div className="divide-y divide-border-light">
            {sigmaRules.map((rule, i) => {
              const style = SEVERITY_STYLES[rule.severity];
              return (
                <div
                  key={`${rule.rule_name}-${i}`}
                  className="flex items-start gap-3 px-4 py-3 hover:bg-bg-hover transition-colors"
                >
                  <div className="flex items-center gap-1 mt-0.5 shrink-0 w-20">
                    <div className="flex gap-0.5">
                      {Array.from({
                        length: rule.severity === "critical" ? 4 : rule.severity === "high" ? 3 : rule.severity === "medium" ? 2 : 1,
                      }).map((_, j) => (
                        <span key={j} className={`w-1.5 h-1.5 rounded-full ${style.dots}`} />
                      ))}
                    </div>
                    <span className={`text-xs capitalize ml-1 ${style.text}`}>
                      {rule.severity}
                    </span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-accent">{rule.rule_name}</p>
                    {rule.description && (
                      <p className="text-xs text-text-secondary mt-0.5">{rule.description}</p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </Section>
      )}
    </div>
  );
}
