import { describe, expect, it } from "vitest";

import {
  analystIdsOf,
  pipelineSteps,
  stepStatus,
  type StageRow,
  type StepFacts,
} from "../pipelineSteps";

const stage = (over: Partial<StageRow>): StageRow => ({
  key: "analysis",
  kind: "analysis",
  ran: true,
  reason: "",
  agents: [],
  duration_ms: 0,
  ...over,
});

const DEFAULT_TEAM: StageRow[] = [
  stage({ agents: ["static", "dynamic", "network"], duration_ms: 1200 }),
  stage({ key: "debate", kind: "debate", duration_ms: 300 }),
  stage({ key: "verdict", kind: "verdict", agents: ["judge"], duration_ms: 90 }),
  stage({ key: "report", kind: "report", agents: ["reporter"], duration_ms: 40 }),
];

describe("pipelineSteps: a run that recorded its stages", () => {
  it("draws the default team as ingestion, three analysts, the debate, the verdict and the report", () => {
    const steps = pipelineSteps({ stages: DEFAULT_TEAM });
    expect(steps.map((s) => s.id)).toEqual([
      "ingestion",
      "static",
      "dynamic",
      "network",
      "negotiation",
      "judge",
      "report",
    ]);
  });

  /* The report stage used to fall through to the judge's tail step, so every
   * staged run drew two "Judge Verdict" rows under one React key. */
  it("does not draw the report stage as a second judge", () => {
    const steps = pipelineSteps({ stages: DEFAULT_TEAM });
    expect(steps.filter((s) => s.id === "judge")).toHaveLength(1);
    expect(steps.find((s) => s.id === "report")?.title).toBe("Report");
  });

  it("gives every row a key that is unique across the list", () => {
    const steps = pipelineSteps({ stages: DEFAULT_TEAM });
    const keys = steps.map((s) => `${s.stage}/${s.id}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("keeps two debates apart", () => {
    const steps = pipelineSteps({
      stages: [
        stage({ key: "one", agents: ["static"] }),
        stage({ key: "argue", kind: "debate" }),
        stage({ key: "two", agents: ["network"] }),
        stage({ key: "argue_again", kind: "debate" }),
        stage({ key: "verdict", kind: "verdict", agents: ["judge"] }),
      ],
    });
    const keys = steps.map((s) => `${s.stage}/${s.id}`);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys).toContain("argue/negotiation");
    expect(keys).toContain("argue_again/negotiation");
  });

  it("carries the reason a stage gave for not running", () => {
    const steps = pipelineSteps({
      stages: [
        stage({ key: "triage", agents: ["static"] }),
        stage({
          key: "apk",
          agents: ["apkscan"],
          ran: false,
          reason: 'condition not met: extension == "apk"',
        }),
        stage({ key: "verdict", kind: "verdict", agents: ["judge"] }),
      ],
    });
    expect(steps.find((s) => s.id === "apkscan")?.skipped).toBe(
      'condition not met: extension == "apk"'
    );
    expect(steps.find((s) => s.id === "static")?.skipped).toBe("");
  });

  it("names a stage that did not run and gave no reason", () => {
    const steps = pipelineSteps({
      stages: [
        stage({ key: "triage", agents: ["static"], ran: false, reason: "" }),
        stage({ key: "verdict", kind: "verdict", agents: ["judge"] }),
      ],
    });
    expect(steps.find((s) => s.id === "static")?.skipped).toBe("did not run");
  });

  it("marks an agent the profile calls custom", () => {
    const steps = pipelineSteps({
      profile: { custom: ["strings"] },
      stages: [
        stage({ agents: ["static", "strings"] }),
        stage({ key: "verdict", kind: "verdict", agents: ["judge"] }),
      ],
    });
    expect(steps.find((s) => s.id === "strings")?.custom).toBe(true);
    expect(steps.find((s) => s.id === "static")?.custom).toBe(false);
  });
});

describe("pipelineSteps: a run stored before stages existed", () => {
  /* Every report already in the database. The claims disclosure is gated on
   * the step being an analyst, so a fallback that left `stageKind` unset hid
   * the findings for static, dynamic and network on every stored run. */
  it("still marks the analysts as analysts", () => {
    const steps = pipelineSteps({ profile: { analysts: ["static", "dynamic", "network"] } });
    expect([...analystIdsOf(steps)]).toEqual(["static", "dynamic", "network"]);
  });

  it("falls back again to the three built-ins when there is no profile at all", () => {
    expect([...analystIdsOf(pipelineSteps(null))]).toEqual(["static", "dynamic", "network"]);
    expect([...analystIdsOf(pipelineSteps({}))]).toEqual(["static", "dynamic", "network"]);
  });

  it("draws the negotiation and judge steps it always drew", () => {
    const steps = pipelineSteps({ profile: { analysts: ["static"] } });
    expect(steps.map((s) => s.id)).toEqual(["ingestion", "static", "negotiation", "judge"]);
  });

  it("treats an empty stage list as no stage list", () => {
    const steps = pipelineSteps({ stages: [], profile: { analysts: ["network"] } });
    expect(steps.map((s) => s.id)).toEqual(["ingestion", "network", "negotiation", "judge"]);
  });
});

describe("analystIdsOf", () => {
  it("names the analysts and nothing else", () => {
    const ids = analystIdsOf(pipelineSteps({ stages: DEFAULT_TEAM }));
    expect([...ids]).toEqual(["static", "dynamic", "network"]);
  });
});

describe("stepStatus", () => {
  const facts = (over: Partial<StepFacts> = {}): StepFacts => ({
    hasReport: true,
    hasVerdict: true,
    hasNegotiation: true,
    negotiationFailed: false,
    hasMalwareReport: true,
    findingStatus: () => "done",
    ...over,
  });

  /* The report stage became a row of its own and fell through to the analyst
   * fallback, which asks for a finding named "report" and never gets one — so
   * the last row of every finished staged run drew grey. */
  it("marks the report row done once a report was built", () => {
    expect(stepStatus("report", facts())).toBe("done");
  });

  it("marks the report row pending when the build produced nothing", () => {
    expect(stepStatus("report", facts({ hasMalwareReport: false }))).toBe("pending");
  });

  it("does not ask for an analyst finding named report", () => {
    const asked: string[] = [];
    stepStatus("report", facts({ findingStatus: (id) => (asked.push(id), "failed") }));
    expect(asked).toEqual([]);
  });

  it("keeps the steps it always had", () => {
    expect(stepStatus("ingestion", facts())).toBe("done");
    expect(stepStatus("judge", facts())).toBe("done");
    expect(stepStatus("judge", facts({ hasVerdict: false }))).toBe("pending");
    expect(stepStatus("negotiation", facts())).toBe("done");
    expect(stepStatus("negotiation", facts({ hasNegotiation: false }))).toBe("pending");
    expect(stepStatus("negotiation", facts({ negotiationFailed: true }))).toBe("failed");
  });

  it("asks the findings for an analyst step", () => {
    expect(stepStatus("static", facts({ findingStatus: () => "failed" }))).toBe("failed");
  });

  it("is pending all the way down for a run with no report row yet", () => {
    for (const id of ["ingestion", "static", "negotiation", "judge", "report"]) {
      expect(stepStatus(id, facts({ hasReport: false }))).toBe("pending");
    }
  });

  it("gives every step of a finished default run a status that is not pending", () => {
    const steps = pipelineSteps({ stages: DEFAULT_TEAM });
    expect(steps.map((s) => stepStatus(s.id, facts()))).toEqual(steps.map(() => "done"));
  });
});
