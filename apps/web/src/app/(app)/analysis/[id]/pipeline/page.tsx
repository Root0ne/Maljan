"use client";

import { useReport } from "../layout";
import { useState } from "react";

/* ── Types for pipeline data ─────────────────────────── */

interface Claim {
  claim?: string;
  description?: string;
  confidence?: number;
  evidence_ref?: string | string[];
  category?: string;
  technique_id?: string;
}

interface AgentFinding {
  agent_name: string;
  domain: string;
  claims: Claim[] | null;
  dissent_items: unknown[] | null;
  revision_rounds: number;
  final_confidence: number;
}

interface NegotiationRound {
  round: number;
  agent: string;
  position?: string;
  confidence: number;
  argument: string;
}

interface NegotiationLog {
  discussion_history?: NegotiationRound[];
  confidence_history?: number[];
  iteration_count?: number;
  is_consensus?: boolean;
}

/* ── Step config ─────────────────────────────────────── */

const PIPELINE_STEPS = [
  {
    id: "ingestion",
    title: "Sample Ingestion",
    description: "File loaded and prepared for analysis.",
  },
  {
    id: "static",
    title: "Static Analysis",
    description: "PE/ELF structure, strings, imports, entropy, YARA rules.",
  },
  {
    id: "dynamic",
    title: "Dynamic Analysis",
    description: "Sandbox execution, behavioral indicators, API calls.",
  },
  {
    id: "network",
    title: "Network Analysis",
    description: "DNS, HTTP, C2 communication patterns, IOC extraction.",
  },
  {
    id: "negotiation",
    title: "Multi-Agent Negotiation",
    description: "Agents debate findings, resolve dissents, converge on consensus.",
  },
  {
    id: "judge",
    title: "Judge Verdict",
    description: "Final classification with STIX 2.1 threat intelligence bundle.",
  },
];

/* ── Helpers ─────────────────────────────────────────── */

function confidenceColor(conf: number): string {
  if (conf >= 75) return "text-status-red";
  if (conf >= 45) return "text-status-orange";
  return "text-status-green";
}

function confidenceBarColor(conf: number): string {
  if (conf >= 75) return "bg-status-red";
  if (conf >= 45) return "bg-status-orange";
  return "bg-status-green";
}

function formatEvidenceRef(ref: string | string[] | undefined): string {
  if (!ref) return "N/A";
  if (Array.isArray(ref)) return ref.join(", ");
  return ref;
}

/* ── Components ──────────────────────────────────────── */

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      className={`w-4 h-4 text-text-muted transition-transform ${open ? "rotate-180" : ""}`}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
    >
      <path d="m6 9 6 6 6-6" />
    </svg>
  );
}

function CollapsibleSection({
  title,
  children,
  defaultOpen = false,
}: {
  title: string;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded mb-3 overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2.5 bg-bg-surface hover:bg-bg-hover transition-colors text-left"
      >
        <span className="text-xs font-medium text-text-primary uppercase tracking-wider">
          {title}
        </span>
        <Chevron open={open} />
      </button>
      {open && <div className="px-4 py-3 bg-bg-deep border-t border-border">{children}</div>}
    </div>
  );
}

function ClaimCard({ claim, index }: { claim: Claim; index: number }) {
  const text = claim.claim || claim.description || "(no text)";
  const conf = typeof claim.confidence === "number" ? Math.round(claim.confidence * 100) : 0;
  return (
    <div className="mb-3 last:mb-0 p-3 bg-bg-surface border border-border-light rounded">
      <div className="flex items-start gap-3">
        <span className="text-xs font-mono text-text-muted shrink-0 mt-0.5">
          #{index + 1}
        </span>
        <div className="flex-1 min-w-0">
          <p className="text-xs text-text-primary leading-relaxed">{text}</p>
          <div className="flex flex-wrap items-center gap-3 mt-2">
            <div className="flex items-center gap-1.5">
              <div className="w-16 h-1.5 bg-bg-deep rounded-sm overflow-hidden">
                <div
                  className={`h-full rounded-sm ${confidenceBarColor(conf)}`}
                  style={{ width: `${Math.min(100, Math.max(0, conf))}%`, opacity: 0.7 }}
                />
              </div>
              <span className={`text-xs font-mono ${confidenceColor(conf)}`}>{conf}%</span>
            </div>
            {claim.category && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-bg-active text-text-muted">
                {claim.category}
              </span>
            )}
            {claim.technique_id && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-bg-active text-text-muted font-mono">
                {claim.technique_id}
              </span>
            )}
          </div>
          {claim.evidence_ref && (
            <div className="mt-1.5 text-[11px] text-text-muted">
              <span className="text-text-secondary">Evidence: </span>
              {formatEvidenceRef(claim.evidence_ref)}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ── Main tab ────────────────────────────────────────── */

export default function PipelineTab() {
  const { report, job, loading } = useReport();
  const [activeStep, setActiveStep] = useState<string | null>(null);

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  if (!report && (!job || job.status !== "completed")) {
    return (
      <div className="p-4 text-sm text-text-secondary animate-pulse">
        Analysis in progress... Pipeline steps will appear here.
      </div>
    );
  }

  const findings: AgentFinding[] = (report?.agent_findings ?? []) as AgentFinding[];
  const negotiation: NegotiationLog | null =
    (report?.negotiation_log as NegotiationLog) ?? null;
  const agentReports = report?.agent_reports ?? null;
  const runSummary = report?.run_summary ?? null;

  // Map agents to steps
  const staticFinding = findings.find((f) =>
    f.agent_name.toLowerCase().includes("static")
  );
  const dynamicFinding = findings.find((f) =>
    f.agent_name.toLowerCase().includes("dynamic")
  );
  const networkFinding = findings.find((f) =>
    f.agent_name.toLowerCase().includes("network")
  );

  const hasNegotiation =
    negotiation &&
    (negotiation.discussion_history?.length || negotiation.iteration_count);

  const stepStatus = (stepId: string): "done" | "current" | "pending" => {
    if (!report) return "pending";
    switch (stepId) {
      case "ingestion":
        return "done";
      case "static":
        return staticFinding ? "done" : "pending";
      case "dynamic":
        return dynamicFinding ? "done" : "pending";
      case "network":
        return networkFinding ? "done" : "pending";
      case "negotiation":
        return hasNegotiation ? "done" : "pending";
      case "judge":
        return report.verdict ? "done" : "pending";
      default:
        return "pending";
    }
  };

  return (
    <div className="space-y-4">
      {/* Pipeline Step Overview */}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Pipeline Execution Flow
          </h2>
        </div>
        <div className="p-4 space-y-2">
          {PIPELINE_STEPS.map((step, idx) => {
            const status = stepStatus(step.id);
            const isActive = activeStep === step.id;
            return (
              <div key={step.id}>
                <button
                  onClick={() => setActiveStep(isActive ? null : step.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded border transition-colors text-left ${
                    status === "done"
                      ? "border-status-green/30 bg-status-green/5 hover:bg-status-green/10"
                      : status === "current"
                      ? "border-status-blue/30 bg-status-blue/5 hover:bg-status-blue/10"
                      : "border-border-light bg-bg-deep hover:bg-bg-hover"
                  }`}
                >
                  <span
                    className={`flex items-center justify-center w-6 h-6 rounded text-[11px] font-mono font-bold shrink-0 ${
                      status === "done"
                        ? "bg-status-green/10 text-status-green"
                        : status === "current"
                        ? "bg-status-blue/10 text-status-blue"
                        : "bg-bg-active text-text-muted"
                    }`}
                  >
                    {idx + 1}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-text-primary">
                        {step.title}
                      </span>
                      {status === "done" && (
                        <span className="text-[11px] px-1.5 py-0.5 rounded bg-status-green/10 text-status-green uppercase tracking-wider">
                          Done
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-text-muted mt-0.5">{step.description}</p>
                  </div>
                  <Chevron open={isActive} />
                </button>

                {/* Step Detail Panel */}
                {isActive && (
                  <div className="mt-2 ml-9 border-l-2 border-border-light pl-4 space-y-3">
                    {step.id === "ingestion" && (
                      <div className="text-xs text-text-secondary space-y-1">
                        <p>
                          <span className="text-text-muted">Job ID:</span> {report?.job_id}
                        </p>
                        <p>
                          <span className="text-text-muted">Status:</span>{" "}
                          {job?.status ?? "unknown"}
                        </p>
                        {job?.config && (
                          <CollapsibleSection title="Job Configuration">
                            <pre className="text-[11px] text-text-muted overflow-auto">
                              {JSON.stringify(job.config, null, 2)}
                            </pre>
                          </CollapsibleSection>
                        )}
                      </div>
                    )}

                    {step.id === "static" && staticFinding && (
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <span className="text-xs text-text-muted">Agent:</span>
                          <span className="text-xs font-medium text-text-primary">
                            {staticFinding.agent_name}
                          </span>
                          <span className="text-xs text-text-muted">Confidence:</span>
                          <span className="text-xs font-mono text-text-primary">
                            {Math.round(staticFinding.final_confidence * 100)}%
                          </span>
                        </div>
                        <CollapsibleSection title={`Claims (${staticFinding.claims?.length ?? 0})`} defaultOpen>
                          {staticFinding.claims && staticFinding.claims.length > 0 ? (
                            staticFinding.claims.map((c, i) => (
                              <ClaimCard key={i} claim={c as Claim} index={i} />
                            ))
                          ) : (
                            <p className="text-xs text-text-muted">No claims recorded.</p>
                          )}
                        </CollapsibleSection>
                        {staticFinding.dissent_items &&
                          staticFinding.dissent_items.length > 0 && (
                            <CollapsibleSection title={`Dissents (${staticFinding.dissent_items.length})`}>
                              <pre className="text-[11px] text-text-muted overflow-auto">
                                {JSON.stringify(staticFinding.dissent_items, null, 2)}
                              </pre>
                            </CollapsibleSection>
                          )}
                      </div>
                    )}

                    {step.id === "dynamic" && dynamicFinding && (
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <span className="text-xs text-text-muted">Agent:</span>
                          <span className="text-xs font-medium text-text-primary">
                            {dynamicFinding.agent_name}
                          </span>
                          <span className="text-xs text-text-muted">Confidence:</span>
                          <span className="text-xs font-mono text-text-primary">
                            {Math.round(dynamicFinding.final_confidence * 100)}%
                          </span>
                        </div>
                        <CollapsibleSection title={`Claims (${dynamicFinding.claims?.length ?? 0})`} defaultOpen>
                          {dynamicFinding.claims && dynamicFinding.claims.length > 0 ? (
                            dynamicFinding.claims.map((c, i) => (
                              <ClaimCard key={i} claim={c as Claim} index={i} />
                            ))
                          ) : (
                            <p className="text-xs text-text-muted">No claims recorded.</p>
                          )}
                        </CollapsibleSection>
                      </div>
                    )}

                    {step.id === "network" && networkFinding && (
                      <div>
                        <div className="flex items-center gap-3 mb-2">
                          <span className="text-xs text-text-muted">Agent:</span>
                          <span className="text-xs font-medium text-text-primary">
                            {networkFinding.agent_name}
                          </span>
                          <span className="text-xs text-text-muted">Confidence:</span>
                          <span className="text-xs font-mono text-text-primary">
                            {Math.round(networkFinding.final_confidence * 100)}%
                          </span>
                        </div>
                        <CollapsibleSection title={`Claims (${networkFinding.claims?.length ?? 0})`} defaultOpen>
                          {networkFinding.claims && networkFinding.claims.length > 0 ? (
                            networkFinding.claims.map((c, i) => (
                              <ClaimCard key={i} claim={c as Claim} index={i} />
                            ))
                          ) : (
                            <p className="text-xs text-text-muted">No claims recorded.</p>
                          )}
                        </CollapsibleSection>
                      </div>
                    )}

                    {step.id === "negotiation" && negotiation && (
                      <div className="space-y-3">
                        <div className="flex items-center gap-4">
                          <span className="text-xs text-text-muted">
                            Rounds:{" "}
                            <strong className="text-text-primary">
                              {negotiation.iteration_count ?? 0}
                            </strong>
                          </span>
                          <span className="text-xs text-text-muted">
                            Consensus:{" "}
                            <strong
                              className={
                                negotiation.is_consensus
                                  ? "text-status-green"
                                  : "text-status-orange"
                              }
                            >
                              {negotiation.is_consensus ? "Yes" : "No"}
                            </strong>
                          </span>
                        </div>

                        {negotiation.confidence_history &&
                          negotiation.confidence_history.length > 0 && (
                            <CollapsibleSection title="Confidence History" defaultOpen>
                              <div className="flex items-end gap-1 h-16">
                                {negotiation.confidence_history.map((v, i) => {
                                  const h = Math.min(100, Math.max(4, v));
                                  return (
                                    <div
                                      key={i}
                                      className="flex-1 flex flex-col items-center gap-1"
                                    >
                                      <div
                                        className="w-full rounded-sm bg-status-blue/60"
                                        style={{ height: `${h}px` }}
                                        title={`Round ${i + 1}: ${v.toFixed(1)}`}
                                      />
                                      <span className="text-[11px] text-text-muted">
                                        {i + 1}
                                      </span>
                                    </div>
                                  );
                                })}
                              </div>
                            </CollapsibleSection>
                          )}

                        {negotiation.discussion_history &&
                          negotiation.discussion_history.length > 0 && (
                            <CollapsibleSection title="Discussion History">
                              <div className="space-y-2">
                                {negotiation.discussion_history.map((round, i) => (
                                  <div
                                    key={i}
                                    className="p-2.5 bg-bg-surface border border-border-light rounded"
                                  >
                                    <div className="flex items-center gap-2 mb-1">
                                      <span className="text-[11px] font-mono text-text-muted">
                                        R{round.round}
                                      </span>
                                      <span className="text-xs font-medium text-text-primary">
                                        {round.agent}
                                      </span>
                                      <span className="text-[11px] text-text-muted">
                                        conf: {Math.round(round.confidence)}%
                                      </span>
                                    </div>
                                    <p className="text-xs text-text-secondary">
                                      {round.argument || "(no argument)"}
                                    </p>
                                  </div>
                                ))}
                              </div>
                            </CollapsibleSection>
                          )}
                      </div>
                    )}

                    {step.id === "judge" && report && (
                      <div className="space-y-3">
                        <div className="grid grid-cols-2 gap-3">
                          <div className="p-3 bg-bg-surface border border-border-light rounded">
                            <span className="text-[11px] text-text-muted uppercase tracking-wider">
                              Verdict
                            </span>
                            <p className="text-sm font-medium text-text-primary capitalize mt-0.5">
                              {report.verdict}
                            </p>
                          </div>
                          <div className="p-3 bg-bg-surface border border-border-light rounded">
                            <span className="text-[11px] text-text-muted uppercase tracking-wider">
                              Confidence
                            </span>
                            <p className="text-sm font-medium text-text-primary mt-0.5">
                              {Math.round(report.overall_confidence * 100)}/100
                            </p>
                          </div>
                        </div>
                        {report.malware_category && (
                          <div className="p-3 bg-bg-surface border border-border-light rounded">
                            <span className="text-[11px] text-text-muted uppercase tracking-wider">
                              Category
                            </span>
                            <p className="text-sm font-medium text-text-primary mt-0.5">
                              {report.malware_category}
                            </p>
                          </div>
                        )}
                        {runSummary && (
                          <CollapsibleSection title="Run Summary">
                            <pre className="text-[11px] text-text-muted overflow-auto">
                              {JSON.stringify(runSummary, null, 2)}
                            </pre>
                          </CollapsibleSection>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Raw Agent Reports */}
      {agentReports && (
        <CollapsibleSection title="Raw Agent Reports (JSON)">
          <pre className="text-[11px] text-text-muted overflow-auto max-h-96">
            {JSON.stringify(agentReports, null, 2)}
          </pre>
        </CollapsibleSection>
      )}

      {/* Full Report JSON */}
      {report && (
        <CollapsibleSection title="Full Report (JSON)">
          <pre className="text-[11px] text-text-muted overflow-auto max-h-96">
            {JSON.stringify(
              {
                id: report.id,
                job_id: report.job_id,
                verdict: report.verdict,
                overall_confidence: report.overall_confidence,
                malware_category: report.malware_category,
                agent_findings: report.agent_findings,
                negotiation_log: report.negotiation_log,
                run_summary: report.run_summary,
                mitre_techniques: report.mitre_techniques,
              },
              null,
              2
            )}
          </pre>
        </CollapsibleSection>
      )}
    </div>
  );
}
