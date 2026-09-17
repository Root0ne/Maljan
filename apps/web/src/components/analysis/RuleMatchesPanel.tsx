"use client";

import { useMemo, useState } from "react";
import { ChevronDown } from "lucide-react";
import { useReport } from "@/app/(app)/analysis/[id]/layout";
import { ruleMatches } from "./ruleMatches";

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
        className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-medium text-text-primary uppercase tracking-wider hover:bg-bg-hover"
      >
        <span>{title}</span>
        <ChevronDown
          size={16}
          aria-hidden="true"
          className={`text-text-muted transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && <div className="border-t border-border">{children}</div>}
    </div>
  );
}

export default function RulesTab() {
  const { report, job, loading } = useReport();

  /* One reading of the run's rule matches, shared with the tab rule that
   * decides whether this panel is reachable at all (`ruleMatches.ts`). */
  const { yara: yaraMatches, sigma: sigmaMatches } = useMemo(
    () => ruleMatches(report?.agent_findings),
    [report?.agent_findings],
  );

  const severityCounts = useMemo(
    () =>
      sigmaMatches.reduce(
        (acc, r) => {
          acc[r.severity] = (acc[r.severity] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      ),
    [sigmaMatches],
  );

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

  // The DETECTION tab draws this section only when a rule fired.
  if (yaraMatches.length === 0 && sigmaMatches.length === 0) return null;

  return (
    <div>
      {yaraMatches.length > 0 && (
        <Section title={`YARA Matches (${yaraMatches.length})`} defaultOpen={true}>
          <div className="bg-status-blue/10 px-4 py-2 border-b border-border">
            <span className="text-xs font-medium text-status-blue uppercase tracking-wider">
              YARA Rules
            </span>
          </div>
          <div className="divide-y divide-border-light">
            {yaraMatches.map((rule, i) => (
              <div
                key={`${rule.rule_name}-${i}`}
                className="flex items-start gap-3 px-4 py-2.5 hover:bg-bg-hover"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-accent">{rule.rule_name}</span>
                    {rule.pattern_count > 0 && (
                      <>
                        <span className="text-text-muted">·</span>
                        <span className="text-text-secondary">
                          {rule.pattern_count} pattern{rule.pattern_count === 1 ? "" : "s"}
                        </span>
                      </>
                    )}
                    {rule.technique_id && (
                      <>
                        <span className="text-text-muted">·</span>
                        <span className="text-text-secondary font-mono">{rule.technique_id}</span>
                      </>
                    )}
                  </div>
                  {rule.evidence && (
                    <p className="text-xs text-text-secondary mt-0.5 truncate">{rule.evidence}</p>
                  )}
                </div>
                <span className="text-xs text-text-muted shrink-0">
                  {Math.round(rule.confidence * 100)}%
                </span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {sigmaMatches.length > 0 && (
        <Section title={`Sigma Matches (${sigmaMatches.length})`} defaultOpen={true}>
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
            {sigmaMatches.map((rule, i) => {
              const style = SEVERITY_STYLES[rule.severity];
              return (
                <div
                  key={`${rule.rule_name}-${i}`}
                  className="flex items-start gap-3 px-4 py-3 hover:bg-bg-hover"
                >
                  <div className="flex items-center gap-1 mt-0.5 shrink-0 w-20">
                    <div className="flex gap-0.5">
                      {Array.from({
                        length:
                          rule.severity === "critical"
                            ? 4
                            : rule.severity === "high"
                              ? 3
                              : rule.severity === "medium"
                                ? 2
                                : 1,
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
                    <div className="flex items-center gap-2 text-xs text-text-secondary mt-0.5">
                      {rule.technique_id && (
                        <span className="font-mono">{rule.technique_id}</span>
                      )}
                      {rule.source && (
                        <>
                          <span className="text-text-muted">·</span>
                          <span>source={rule.source}</span>
                        </>
                      )}
                    </div>
                    {rule.evidence && (
                      <p className="text-xs text-text-muted mt-1 truncate">{rule.evidence}</p>
                    )}
                  </div>
                  <span className="text-xs text-text-muted shrink-0">
                    {Math.round(rule.confidence * 100)}%
                  </span>
                </div>
              );
            })}
          </div>
        </Section>
      )}
    </div>
  );
}
