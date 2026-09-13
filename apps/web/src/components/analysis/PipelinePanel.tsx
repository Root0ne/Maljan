"use client";

import { useReport } from "@/app/(app)/analysis/[id]/layout";
import { useState } from "react";
import { confidenceBarColor, confidenceClass } from "@/lib/report-utils";
import { verdictLabel } from "@/lib/verdict";
import { analystIdsOf, pipelineSteps, stepStatus as statusOfStep } from "./pipelineSteps";
import type { PipelineStep } from "./pipelineSteps";
import {
  formatStageDuration,
  hasStageRecord,
  stageTimeline,
  type StageStatus,
} from "./stageTimeline";

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
  /** The lifecycle status the worker derives from the ISR shape. A crashed
   *  analyst still writes a row, so this is the only thing that says whether
   *  the step actually succeeded. */
  status?: "complete" | "no_data" | "failed" | "timeout";
}

interface NegotiationRound {
  round: number;
  agent: string;
  position?: string;
  confidence: number;
  argument: string;
  /** "complete" | "failed" | "timeout"; absent on rows stored before the
   *  backend carried it. */
  status?: string;
}

interface NegotiationLog {
  discussion_history?: NegotiationRound[];
  confidence_history?: number[];
  iteration_count?: number;
  is_consensus?: boolean;
  mediation_failed?: boolean;
}

/* ── Step config ─────────────────────────────────────── */

/* ── Helpers ─────────────────────────────────────────── */

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
          <p className="text-sm text-text-primary leading-relaxed">{text}</p>
          <div className="flex flex-wrap items-center gap-3 mt-2">
            <div className="flex items-center gap-1.5">
              <div className="w-16 h-1.5 bg-bg-deep rounded-sm overflow-hidden">
                <div
                  className={`h-full rounded-sm ${confidenceBarColor(conf)}`}
                  style={{ width: `${Math.min(100, Math.max(0, conf))}%`, opacity: 0.7 }}
                />
              </div>
              <span className={`text-xs font-mono ${confidenceClass(conf)}`}>{conf}%</span>
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

const STAGE_STATUS_STYLE: Record<StageStatus, string> = {
  running: "border-status-blue/30 bg-status-blue/5 text-status-blue",
  done: "border-status-green/30 bg-status-green/5 text-status-green",
  skipped: "border-border-light bg-bg-deep text-text-muted",
  pending: "border-border-light bg-bg-deep text-text-muted",
};

/**
 * One row per stage of the team, in the order the run reaches them.
 *
 * This is the shape of the analysis now: not a fixed chain of four steps but
 * whichever stages the active profile declares, each with the agents it ran,
 * whether it ran at all and why not. The analyst rows nest underneath their
 * stage rather than beside it, so a team of six stages reads as six things
 * that happened instead of fourteen.
 */
function StageTimeline({
  stages,
  children,
}: {
  stages: ReturnType<typeof stageTimeline>;
  /** The step rows belonging to one stage, drawn inside its row. */
  children?: (stageKey: string) => React.ReactNode;
}) {
  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          Stages
        </h2>
      </div>
      <div className="p-4 space-y-3">
        {stages.map((stage) => (
          <div key={stage.key}>
            <div
              className={`flex flex-wrap items-baseline gap-2 px-3 py-2 rounded border ${STAGE_STATUS_STYLE[stage.status]}`}
            >
              <span className="text-xs font-mono font-medium text-text-primary">
                {stage.key}
              </span>
              {stage.kind && (
                <span className="text-[10px] uppercase tracking-wider text-text-muted">
                  {stage.kind}
                </span>
              )}
              <span className="text-[11px] uppercase tracking-wider">{stage.status}</span>
              {stage.agents.length > 0 && (
                <span className="text-[11px] text-text-muted font-mono">
                  {stage.agents.join(", ")}
                </span>
              )}
              {formatStageDuration(stage.duration_ms) && (
                <span className="ml-auto text-[11px] text-text-muted tabular-nums">
                  {formatStageDuration(stage.duration_ms)}
                </span>
              )}
              {stage.reason && (
                <span className="w-full text-[11px] text-text-muted">{stage.reason}</span>
              )}
            </div>
            {children && (
              <div className="mt-2 ml-4 border-l-2 border-border-light pl-3 space-y-2">
                {children(stage.key)}
              </div>
            )}
          </div>
        ))}
        {stages.length === 0 && (
          <p className="text-xs text-text-muted">
            This run recorded no stages. It predates the staged team.
          </p>
        )}
      </div>
    </div>
  );
}

/* ── Main tab ────────────────────────────────────────── */

export default function PipelineTab() {
  const { report, job, loading, events } = useReport();
  const [activeStep, setActiveStep] = useState<string | null>(null);

  // The team, from the live events while the run is happening and from the
  // stored rollup afterwards. Read before the early returns because a running
  // job has stages and no report at all, and the stage timeline is the one
  // thing this tab can show for the whole half hour that lasts.
  const storedStages = report?.run_summary?.stages ?? null;
  const stages = stageTimeline(events, storedStages);
  const staged = hasStageRecord(events, storedStages);

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  if (!report && (!job || job.status !== "completed")) {
    return (
      <div className="space-y-4">
        {staged ? (
          <StageTimeline stages={stages} />
        ) : (
          <div className="p-4 text-sm text-text-secondary animate-pulse">
            Analysis in progress... Pipeline steps will appear here.
          </div>
        )}
      </div>
    );
  }

  const findings: AgentFinding[] = (report?.agent_findings ?? []) as AgentFinding[];
  const negotiation: NegotiationLog | null =
    (report?.negotiation_log as NegotiationLog) ?? null;
  // `agent_reports` is `Record<agentName, prose>`; the type is loose because
  // it is a JSONB column. Filter to the string values so a malformed row
  // cannot put `[object Object]` on the page — there is no error boundary in
  // this app, and the tab walk in e2e asserts zero page errors.
  const agentReportEntries = Object.entries(report?.agent_reports ?? {}).filter(
    (entry): entry is [string, string] =>
      typeof entry[1] === "string" && entry[1].trim().length > 0
  );
  const runSummary = report?.run_summary ?? null;

  const steps = pipelineSteps(runSummary);
  const analystIds = analystIdsOf(steps);
  const findingFor = (id: string) =>
    findings.find((f) => f.agent_name.toLowerCase() === id.toLowerCase()) ??
    findings.find((f) => f.agent_name.toLowerCase().includes(id.toLowerCase()));

  const hasNegotiation =
    negotiation &&
    (negotiation.discussion_history?.length || negotiation.iteration_count);

  /* A negotiation that errored on every round still had rounds and an
   * iteration count, so this step rendered a green "Done" for runs where the
   * mediator never once produced a ruling. Every run in the database looked
   * like a successful negotiation. */
  const negotiationFailed =
    negotiation?.mediation_failed === true ||
    (negotiation?.discussion_history ?? []).some(
      (r) =>
        r.agent === "Mediator" &&
        (r.status === "failed" ||
          r.status === "timeout" ||
          String(r.argument ?? "").startsWith("[ERROR] Mediation"))
    );

  const findingStatus = (
    f: AgentFinding | undefined
  ): "done" | "pending" | "failed" => {
    if (!f) return "pending";
    return f.status === "failed" || f.status === "timeout" ? "failed" : "done";
  };

  const stepStatus = (stepId: string) =>
    statusOfStep(stepId, {
      hasReport: Boolean(report),
      hasVerdict: Boolean(report?.verdict),
      hasNegotiation: Boolean(hasNegotiation),
      negotiationFailed,
      hasMalwareReport: Boolean(report?.malware_report),
      findingStatus: (id) => findingStatus(findingFor(id)),
    });

  const renderStep = (step: PipelineStep, idx: number) => {
    const status = stepStatus(step.id);
    const isActive = activeStep === step.id;
    return (
    // Keyed on the stage as well as the step id: two stages can
    // contribute a step with the same id only if a team holds two of
    // one kind, and React must still tell those rows apart.
    <div key={`${step.stage}/${step.id}`}>
      <button
        onClick={() => setActiveStep(isActive ? null : step.id)}
        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded border transition-colors text-left ${
          status === "done"
            ? "border-status-green/30 bg-status-green/5 hover:bg-status-green/10"
            : status === "failed"
            ? "border-status-red/30 bg-status-red/5 hover:bg-status-red/10"
            : status === "current"
            ? "border-status-blue/30 bg-status-blue/5 hover:bg-status-blue/10"
            : "border-border-light bg-bg-deep hover:bg-bg-hover"
        }`}
      >
        <span
          className={`flex items-center justify-center w-6 h-6 rounded text-[11px] font-mono font-bold shrink-0 ${
            status === "done"
              ? "bg-status-green/10 text-status-green"
              : status === "failed"
              ? "bg-status-red/10 text-status-red"
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
            {step.custom && (
              <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/20 text-accent-strong">
                custom
              </span>
            )}
            {step.stage !== step.id && step.stage !== "ingestion" && (
              <span
                className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-bg-active text-text-muted"
                title={`stage kind: ${step.stageKind}`}
              >
                {step.stage}
              </span>
            )}
            {step.skipped && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-bg-active text-text-muted">
                skipped — {step.skipped}
              </span>
            )}
            {status === "done" && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-status-green/10 text-status-green uppercase tracking-wider">
                Done
              </span>
            )}
            {status === "failed" && (
              <span className="text-[11px] px-1.5 py-0.5 rounded bg-status-red/10 text-status-red uppercase tracking-wider">
                Did not run
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

          {step.id !== "ingestion" &&
            step.id !== "negotiation" &&
            step.id !== "judge" &&
            analystIds.has(step.id) &&
            (() => {
              const finding = findingFor(step.id);
              if (!finding) return null;
              return (
                <div>
                  <div className="flex items-center gap-3 mb-2">
                    <span className="text-xs text-text-muted">Agent:</span>
                    <span className="text-xs font-medium text-text-primary">
                      {finding.agent_name}
                    </span>
                    <span className="text-xs text-text-muted">Confidence:</span>
                    <span className="text-xs font-mono text-text-primary">
                      {Math.round(finding.final_confidence * 100)}%
                    </span>
                  </div>
                  <CollapsibleSection
                    title={`Claims (${finding.claims?.length ?? 0})`}
                    defaultOpen
                  >
                    {finding.claims && finding.claims.length > 0 ? (
                      finding.claims.map((c, i) => (
                        <ClaimCard key={i} claim={c as Claim} index={i} />
                      ))
                    ) : (
                      <p className="text-xs text-text-muted">No claims recorded.</p>
                    )}
                  </CollapsibleSection>
                  {/* Only static ever showed this pre-profile; keeping dynamic
                     and network silent here preserves the built-in report's
                     presentation exactly, while a custom analyst still gets it. */}
                  {(step.id === "static" || step.custom) &&
                    finding.dissent_items &&
                    finding.dissent_items.length > 0 && (
                      <CollapsibleSection title={`Dissents (${finding.dissent_items.length})`}>
                        <pre className="text-[11px] text-text-muted overflow-auto">
                          {JSON.stringify(finding.dissent_items, null, 2)}
                        </pre>
                      </CollapsibleSection>
                    )}
                </div>
              );
            })()}

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
                  {/* The backend emits "Malware"; every surface
                      must show the normalised "Malicious". */}
                  <p className="text-sm font-medium text-text-primary mt-0.5">
                    {verdictLabel(report.verdict)}
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
  };

  return (
    <div className="space-y-4">
      {staged ? (
        <>
          <StageTimeline stages={stages}>
            {(key) =>
              steps
                .map((step, idx) => [step, idx] as const)
                .filter(([step]) => step.stage === key)
                .map(([step, idx]) => renderStep(step, idx))
            }
          </StageTimeline>
          {/* Ingestion is not a stage of the team — it is what happened before
              the team was handed anything — so it keeps a row of its own. */}
          <div className="bg-bg-surface border border-border rounded">
            <div className="p-4 space-y-2">
              {steps
                .map((step, idx) => [step, idx] as const)
                .filter(([step]) => step.stageKind === "ingestion")
                .map(([step, idx]) => renderStep(step, idx))}
            </div>
          </div>
        </>
      ) : (
        /* A run stored before the team was stages has no stage record, and its
           flat chain is exactly what it was: rendered the way it always was. */
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Pipeline Execution Flow
            </h2>
          </div>
          <div className="p-4 space-y-2">{steps.map((step, idx) => renderStep(step, idx))}</div>
        </div>
      )}

      {/* Each agent's written report.
       *
       * This was a `JSON.stringify` of the whole `agent_reports` object — a
       * wall of escaped newlines that technically contained the analysts'
       * prose and in practice nobody read. The reports are the most readable
       * thing the pipeline produces; the only reason they looked like data was
       * that they were rendered as data. Same payload, one section per agent,
       * as text. The transcript on the PROCESS tab shows the same prose
       * per round, in context. */}
      {agentReportEntries.length > 0 && (
        <CollapsibleSection title="Agent reports">
          <div className="space-y-4">
            {agentReportEntries.map(([name, body]) => (
              <div key={name}>
                <h4 className="text-xs font-medium text-text-primary uppercase tracking-wider mb-1">
                  {name}
                </h4>
                <p className="text-xs text-text-secondary leading-relaxed whitespace-pre-wrap break-words max-h-96 overflow-y-auto">
                  {body}
                </p>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}
    </div>
  );
}
