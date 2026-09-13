/**
 * The rows the pipeline panel draws, derived from a stored run.
 *
 * Its own module rather than a helper inside the panel because it is the part
 * with rules in it — which steps a run had, which stage each belongs to, and
 * what a run stored before stages looks like — and those rules are worth
 * testing without mounting React.
 */

export type StageKind = "analysis" | "debate" | "verdict" | "report";

export interface StageRow {
  key: string;
  kind: StageKind;
  ran: boolean;
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
    const skipped = stage.ran ? "" : stage.reason || "did not run";
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

/** The analyst steps of a step list, for the findings disclosure. */
export function analystIdsOf(steps: PipelineStep[]): Set<string> {
  return new Set(steps.filter((step) => step.stageKind === "analysis").map((step) => step.id));
}
