"use client";

import { useMemo, useState } from "react";
import { useReport } from "../layout";
import type { AgentFinding } from "@/types";

interface ClaimRecord {
  claim: string;
  confidence: number;
  evidence_ref: string;
  technique_id: string;
}

interface YaraMatch {
  rule_name: string;
  pattern_count: number;
  technique_id: string;
  evidence: string;
  confidence: number;
}

interface SigmaMatch {
  rule_name: string;
  technique_id: string;
  source: string;
  evidence: string;
  confidence: number;
  severity: "critical" | "high" | "medium" | "low";
}

const SEVERITY_STYLES: Record<string, { dots: string; text: string }> = {
  critical: { dots: "bg-status-red", text: "text-status-red" },
  high: { dots: "bg-status-orange", text: "text-status-orange" },
  medium: { dots: "bg-status-blue", text: "text-status-blue" },
  low: { dots: "bg-text-muted", text: "text-text-muted" },
};

/* ── Claim parsers ─────────────────────────────────────
 * The deterministic layers (src/maljan/analysis/yara_layer.py +
 * sigma_layer.py) emit free-text claims like:
 *
 *   "Deterministic YARA signature match: Virtualization and sandbox
 *    evasion (rule: sandbox_evasion, 1 pattern(s) found)"
 *
 *   "Sigma rule detection: Suspicious DNS Z Flag Bit Set (technique
 *    T1095, source=generic)"
 *
 * The shape is stable enough to extract rule_name + pattern_count /
 * source via regex without a schema change.
 */
function parseYara(c: ClaimRecord): YaraMatch {
  const ruleMatch = /rule:\s*([^,)\s]+)/i.exec(c.claim);
  const patternMatch = /(\d+)\s+pattern/i.exec(c.claim);
  return {
    rule_name: ruleMatch?.[1] ?? c.claim.split(":").slice(1).join(":").trim() ?? "unknown",
    pattern_count: patternMatch ? Number(patternMatch[1]) : 0,
    technique_id: c.technique_id || "",
    evidence: c.evidence_ref || "",
    confidence: c.confidence ?? 0,
  };
}

function parseSigma(c: ClaimRecord): SigmaMatch {
  const nameMatch = /Sigma rule detection:\s*(.+?)\s*\(technique\s+([^,)]+)(?:,\s*source=([^)]+))?\)/i.exec(
    c.claim,
  );
  const ruleName = nameMatch?.[1] ?? c.claim;
  const technique = nameMatch?.[2] ?? c.technique_id ?? "";
  const source = nameMatch?.[3] ?? "";
  // The deterministic Sigma layer doesn't surface a severity per match,
  // so derive a rough one from confidence. >=0.9 critical, >=0.7 high,
  // >=0.5 medium, else low. Real Sigma severity would live in claim
  // payload once the layer plumbs it through.
  const conf = c.confidence ?? 0;
  const severity: SigmaMatch["severity"] =
    conf >= 0.9 ? "critical" : conf >= 0.7 ? "high" : conf >= 0.5 ? "medium" : "low";
  return {
    rule_name: ruleName.trim(),
    technique_id: technique.trim(),
    source: source.trim(),
    evidence: c.evidence_ref || "",
    confidence: conf,
    severity,
  };
}

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

function findingsByName(
  findings: AgentFinding[] | undefined,
  name: string,
): ClaimRecord[] {
  const row = findings?.find((f) => f.agent_name === name);
  if (!row || !Array.isArray(row.claims)) return [];
  return row.claims
    .filter((c): c is Record<string, unknown> => !!c && typeof c === "object")
    .map((c) => ({
      claim: String((c as Record<string, unknown>).claim ?? ""),
      confidence: Number((c as Record<string, unknown>).confidence ?? 0),
      evidence_ref: String((c as Record<string, unknown>).evidence_ref ?? ""),
      technique_id: String((c as Record<string, unknown>).technique_id ?? ""),
    }));
}

export default function RulesTab() {
  const { report, job, loading } = useReport();

  const { yaraMatches, sigmaMatches } = useMemo(() => {
    const findings = report?.agent_findings;
    return {
      yaraMatches: findingsByName(findings, "yara_layer").map(parseYara),
      sigmaMatches: findingsByName(findings, "sigma_layer").map(parseSigma),
    };
  }, [report?.agent_findings]);

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

  const hasData = yaraMatches.length > 0 || sigmaMatches.length > 0;
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
                className="flex items-start gap-3 px-4 py-2.5 hover:bg-bg-hover transition-colors"
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
                  className="flex items-start gap-3 px-4 py-3 hover:bg-bg-hover transition-colors"
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
