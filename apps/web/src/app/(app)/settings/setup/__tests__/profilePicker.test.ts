import { describe, expect, it } from "vitest";
import type { ProfileEntry, StageEntry } from "@/types/settings";

import { analysisStages, withAgentInStage, withoutProfile } from "../steps/profilePicker";

const stage = (over: Partial<StageEntry>): StageEntry => ({
  key: "analysis",
  label: "",
  kind: "analysis",
  agents: [],
  depends_on: [],
  when: "",
  mode: "sequential",
  inject_upstream: "none",
  debate: null,
  builtin_tools: true,
  ...over,
});

const team = (label: string, ...stages: StageEntry[]): ProfileEntry => ({
  label,
  stages: [
    ...stages,
    stage({ key: "verdict", kind: "verdict", agents: ["judge"], depends_on: [stages[0].key] }),
  ],
  analysts: [],
});

const profiles = (): Record<string, ProfileEntry> => ({
  default: team("Default", stage({ agents: ["static", "dynamic"] })),
  quick: team("", stage({ agents: ["static"] })),
  wide: team(
    "Wide",
    stage({ key: "triage", agents: ["static"] }),
    stage({ key: "deep", agents: ["dynamic"], depends_on: ["triage"] })
  ),
});

const agentsOf = (profile: ProfileEntry, key: string) =>
  profile.stages.find((s) => s.key === key)?.agents;

describe("analysisStages", () => {
  it("names the analysis stages and nothing else", () => {
    expect(analysisStages(profiles().wide)).toEqual(["triage", "deep"]);
  });

  it("is empty for a team that is not there", () => {
    expect(analysisStages(undefined)).toEqual([]);
  });
});

describe("withAgentInStage", () => {
  it("appends the agent to the first analysis stage, keeping the label", () => {
    const next = withAgentInStage(profiles(), "quick", "yara");
    expect(agentsOf(next.quick, "analysis")).toEqual(["static", "yara"]);
    expect(next.quick.label).toBe("");
    expect(next.default).toEqual(profiles().default);
  });

  it("puts the agent in the stage it was told to", () => {
    const next = withAgentInStage(profiles(), "wide", "yara", "deep");
    expect(agentsOf(next.wide, "triage")).toEqual(["static"]);
    expect(agentsOf(next.wide, "deep")).toEqual(["dynamic", "yara"]);
  });

  it("does not add an agent the team already runs in another stage", () => {
    const next = withAgentInStage(profiles(), "wide", "dynamic", "triage");
    expect(next.wide).toEqual(profiles().wide);
  });

  it("creates a missing team from the named source, with the copy label", () => {
    const next = withAgentInStage(profiles(), "triage", "yara", undefined, "default");
    expect(next.triage.label).toBe("Default (copy)");
    expect(agentsOf(next.triage, "analysis")).toEqual(["static", "dynamic", "yara"]);
    expect(Object.keys(next)).toEqual(["default", "quick", "wide", "triage"]);
  });

  it("names a copy of an unlabelled source after the new key", () => {
    const next = withAgentInStage(profiles(), "triage", "yara", undefined, "quick");
    expect(next.triage.label).toBe("triage");
    expect(agentsOf(next.triage, "analysis")).toEqual(["static", "yara"]);
  });

  it("creates a four-stage team of just the agent when there is no source", () => {
    const solo = withAgentInStage(profiles(), "solo", "yara").solo;
    expect(solo.label).toBe("solo");
    expect(solo.stages.map((s) => s.kind)).toEqual(["analysis", "debate", "verdict", "report"]);
    expect(agentsOf(solo, "analysis")).toEqual(["yara"]);
  });

  it("leaves the map it was given alone", () => {
    const before = profiles();
    withAgentInStage(before, "quick", "yara");
    expect(before).toEqual(profiles());
  });
});

describe("withoutProfile", () => {
  it("drops only the named team", () => {
    const rest = withoutProfile(profiles(), "quick");
    expect(Object.keys(rest)).toEqual(["default", "wide"]);
  });

  it("is a no-op for a team that is not there", () => {
    expect(withoutProfile(profiles(), "nope")).toEqual(profiles());
  });
});
