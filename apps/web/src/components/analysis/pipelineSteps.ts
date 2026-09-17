/**
 * The rows the pipeline panel draws, derived from a stored run.
 *
 * Its own module rather than a helper inside the panel because it is the part
 * with rules in it — which steps a run had, which stage each belongs to, and
 * what a run stored before stages looks like — and those rules are worth
 * testing without mounting React.
 */

export type StageKind = "triage" | "analysis" | "debate" | "verdict" | "report";

export interface StageRow {
  key: string;
  kind: StageKind;
  ran: boolean;
  /** The stage ran and went wrong; `reason` says how. */
  failure?: boolean;
  reason: string;
  agents: string[];
  duration_ms: number;
}

export interface PipelineStep {
  /** What `stepStatus` and the findings lookup key on. */
  id: string;
  title: string;
  description: string;
  custom: boolean;
  /** The stage this step belongs to. Always set: a run stored before stages
   *  is read as the four the pipeline has always had. */
  stage: string;
  stageKind: StageKind | "ingestion";
  /** Why the stage declined to run. Empty when it ran. */
  skipped: string;
}

export const INGESTION_STEP = {
  id: "ingestion",
  title: "Sample Ingestion",
  description: "File loaded and prepared for analysis.",
  custom: false,
  stage: "ingestion",
  stageKind: "ingestion" as const,
  skipped: "",
};

/** The non-analyst steps, one per stage kind that contributes one. */
export const KIND_STEPS: Record<
  Exclude<StageKind, "analysis">,
  { id: string; title: string; description: string }
> = {
  triage: {
    id: "triage",
    title: "Triage pack",
    description: "The deterministic tools, run by the pipeline and written to the evidence ledger.",
  },
  debate: {
    id: "negotiation",
    title: "Multi-Agent Negotiation",
    description: "Agents debate findings, resolve dissents, converge on consensus.",
  },
  verdict: {
    id: "judge",
    title: "Judge Verdict",
    description: "Final classification with STIX 2.1 threat intelligence bundle.",
  },
  report: {
    id: "report",
    title: "Report",
    description: "The analysis report, built from the verdict and the evidence behind it.",
  },
};

/** What each built-in analyst step said before the profile decided the list. */
export const BUILTIN_ANALYST_STEPS: Record<string, { title: string; description: string }> = {
  static: {
    title: "Static Analysis",
    description: "PE/ELF structure, strings, imports, entropy, YARA rules.",
  },
  dynamic: {
    title: "Dynamic Analysis",
    description: "Sandbox execution, behavioral indicators, API calls.",
  },
  network: {
    title: "Network Analysis",
    description: "DNS, HTTP, C2 communication patterns, IOC extraction.",
  },
};

interface RunSummaryShape {
  profile?: { analysts?: string[]; custom?: string[] };
  stages?: StageRow[];
  budget?: Record<string, { caps?: string[] } | null> | null;
}

/** What each cap the budget meter names means to a reader. */
export const CAP_LABEL: Record<string, string> = {
  steps: "ended at its step cap",
  time: "ended at its time cap",
  repeats: "ended on repeated calls",
  budget_seconds: "ended at the pack's budget",
};

/**
 * The caps that ended an agent's work, from `run_summary.budget`.
 *
 * Empty for a step that is not an agent, for a run stored before the meter
 * existed, and for an agent whose loops all ended on an answer.
 */
export function capsHit(runSummary: unknown, agentId: string): string[] {
  const summary = (runSummary ?? null) as RunSummaryShape | null;
  const row = summary?.budget?.[agentId];
  if (!row || !Array.isArray(row.caps)) return [];
  return row.caps.filter((cap): cap is string => typeof cap === "string" && cap.length > 0);
}

/**
 * The steps this run actually had.
 *
 * `run_summary.stages` is the whole team, in order, including the stages that
 * declined to run and the reason each gave. It is what this reads first. A
 * report written before stages existed has no such key, so `profile.analysts`
 * is the fallback, and one written before profiles existed falls back again to
 * the three built-in ids — every old report renders exactly as it did, with
 * the four stage names the pipeline has always had filled in around it.
 *
 * An analysis stage becomes one step per agent, because that is the grain the
 * findings are keyed by; every other kind contributes one step with the id the
 * panel has always used, so the sections underneath do not move.
 */
export function pipelineSteps(runSummary: unknown): PipelineStep[] {
  const summary = (runSummary ?? null) as RunSummaryShape | null;
  const custom = new Set(summary?.profile?.custom ?? []);

  const analystStep = (
    id: string,
    stage: string,
    skipped = ""
  ): PipelineStep => ({
    id,
    title: BUILTIN_ANALYST_STEPS[id]?.title ?? `${id} analysis`,
    description:
      BUILTIN_ANALYST_STEPS[id]?.description ?? "A custom analyst declared in the settings.",
    custom: custom.has(id),
    stage,
    stageKind: "analysis",
    skipped,
  });

  const kindStep = (kind: Exclude<StageKind, "analysis">, stage: string, skipped: string) => ({
    ...KIND_STEPS[kind],
    custom: false,
    stage,
    stageKind: kind,
    skipped,
  });

  const stages = Array.isArray(summary?.stages) ? summary.stages : null;
  if (!stages || stages.length === 0) {
    const analysts = summary?.profile?.analysts ?? ["static", "dynamic", "network"];
    return [
      INGESTION_STEP,
      ...analysts.map((id) => analystStep(id, "analysis")),
      kindStep("debate", "debate", ""),
      kindStep("verdict", "verdict", ""),
    ];
  }

  const steps: PipelineStep[] = [INGESTION_STEP];
  for (const stage of stages) {
    // A stage that ran and failed — a crashed pack, a mediation that timed
    // out — says so here rather than drawing as done.
    const skipped = stage.ran
      ? stage.failure
        ? `failed: ${stage.reason || "the stage failed"}`
        : ""
      : stage.reason || "did not run";
    if (stage.kind === "analysis") {
      steps.push(...(stage.agents ?? []).map((id) => analystStep(id, stage.key, skipped)));
      continue;
    }
    const step = KIND_STEPS[stage.kind as Exclude<StageKind, "analysis">];
    // A kind this build does not draw is left out rather than folded into
    // whichever step happened to match: the report stage used to fall through
    // to the judge's row and every staged run drew two "Judge Verdict"s.
    if (step) steps.push(kindStep(stage.kind as Exclude<StageKind, "analysis">, stage.key, skipped));
  }
  return steps;
}

export type StepStatus = "done" | "current" | "pending" | "failed";

/** What a run has produced, as the step list needs to read it. */
export interface StepFacts {
  /** A persisted report exists at all. Nothing is ``done`` without one. */
  hasReport: boolean;
  hasVerdict: boolean;
  hasNegotiation: boolean;
  negotiationFailed: boolean;
  /** The report stage's own output — the built ``MalwareReport``. */
  hasMalwareReport: boolean;
  /** The status of the analyst finding with this id, for an analyst step. */
  findingStatus: (stepId: string) => StepStatus;
}

/**
 * Whether a step of this run is done, still pending, or failed.
 *
 * Every non-analyst step needs a case of its own: the fallback asks for an
 * analyst finding by the step id, and there is no finding named ``judge`` or
 * ``report``. When the report stage became a row of its own it fell through to
 * that fallback and drew grey on every finished run, telling the operator the
 * report had never happened.
 */
export function stepStatus(stepId: string, facts: StepFacts): StepStatus {
  if (!facts.hasReport) return "pending";
  switch (stepId) {
    case "ingestion":
      return "done";
    // The pack has no finding of its own; a run that reached a report either
    // ran it or recorded that it declined, and both are over.
    case "triage":
      return "done";
    case "negotiation":
      if (facts.negotiationFailed) return "failed";
      return facts.hasNegotiation ? "done" : "pending";
    case "judge":
      return facts.hasVerdict ? "done" : "pending";
    case "report":
      // A run whose report build raised persists the verdict and no
      // ``malware_report``, and that is exactly the case this row is for.
      return facts.hasMalwareReport ? "done" : "pending";
    // An analyst that crashed still leaves a findings row, so "a row exists"
    // was never the same question as "the step succeeded".
    default:
      return facts.findingStatus(stepId);
  }
}

/** The analyst steps of a step list, for the findings disclosure. */
export function analystIdsOf(steps: PipelineStep[]): Set<string> {
  return new Set(steps.filter((step) => step.stageKind === "analysis").map((step) => step.id));
}
