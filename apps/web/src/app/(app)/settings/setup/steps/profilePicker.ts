import type { ProfileEntry, StageEntry } from "@/types/settings";

/** The keys of a team's analysis stages, in the order the team declares them. */
export function analysisStages(profile: ProfileEntry | undefined): string[] {
  return (profile?.stages ?? []).filter((s) => s.kind === "analysis").map((s) => s.key);
}

const cloneStages = (stages: StageEntry[]): StageEntry[] =>
  stages.map((s) => ({ ...s, agents: [...s.agents], depends_on: [...s.depends_on] }));

/** The four stages a team starts from when there is nothing to copy. */
function starterStages(): StageEntry[] {
  const base = {
    label: "",
    when: "",
    mode: null,
    inject_upstream: "none" as const,
    debate: null,
    builtin_tools: true,
  };
  return [
    { ...base, key: "analysis", kind: "analysis", agents: [], depends_on: [] },
    { ...base, key: "debate", kind: "debate", agents: [], depends_on: ["analysis"] },
    { ...base, key: "verdict", kind: "verdict", agents: ["judge"], depends_on: ["debate"] },
    { ...base, key: "report", kind: "report", agents: ["reporter"], depends_on: ["verdict"] },
  ];
}

/**
 * The profile map with `agentKey` in one stage of `profileKey`.
 *
 * An existing team keeps everything it has and gains the agent at the end of
 * the named stage — or of its first analysis stage, when the caller has no
 * preference — unless it already runs it: an operator who walks back through
 * the guide must not end up with the same analyst twice, and a profile may
 * not name one agent in two stages at all.
 *
 * A team that does not exist yet is created from `from`, the team the guide
 * offered to copy (the active one): its stages, plus the agent, and the label
 * the console's Clone gives a copy — `"<label> (copy)"`, falling back to the
 * new key when the source has no label, exactly as `StagesEditor.add()` names
 * one.
 */
export function withAgentInStage(
  profiles: Record<string, ProfileEntry>,
  profileKey: string,
  agentKey: string,
  stageKey?: string,
  from?: string
): Record<string, ProfileEntry> {
  const target = profiles[profileKey];
  if (target) {
    if ((target.stages ?? []).some((s) => s.agents.includes(agentKey))) return { ...profiles };
    const stages = cloneStages(target.stages ?? []);
    const index = pickStage(stages, stageKey);
    if (index === -1) return { ...profiles };
    stages[index].agents.push(agentKey);
    return { ...profiles, [profileKey]: { ...target, stages } };
  }
  const source = from ? profiles[from] : undefined;
  const stages = source?.stages?.length ? cloneStages(source.stages) : starterStages();
  const index = pickStage(stages, stageKey);
  if (index !== -1 && !stages[index].agents.includes(agentKey)) {
    stages[index].agents.push(agentKey);
  }
  return {
    ...profiles,
    [profileKey]: {
      label: source?.label ? `${source.label} (copy)` : profileKey,
      stages,
      analysts: [],
    },
  };
}

function pickStage(stages: StageEntry[], stageKey: string | undefined): number {
  if (stageKey) {
    const named = stages.findIndex((s) => s.key === stageKey && s.kind === "analysis");
    if (named !== -1) return named;
  }
  return stages.findIndex((s) => s.kind === "analysis");
}

/** The map without `key`, leaving every other team as it was. */
export function withoutProfile(
  profiles: Record<string, ProfileEntry>,
  key: string
): Record<string, ProfileEntry> {
  const out = { ...profiles };
  delete out[key];
  return out;
}
