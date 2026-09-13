import { describe, expect, it } from "vitest";

import type { StageRow } from "../pipelineSteps";
import {
  formatStageDuration,
  hasStageRecord,
  stageTimeline,
  toolCallsByAgent,
  type StageEvent,
} from "../stageTimeline";

function stored(over: Partial<StageRow> = {}): StageRow {
  return {
    key: "analysis",
    kind: "analysis",
    ran: true,
    reason: "",
    agents: ["static", "dynamic"],
    duration_ms: 4200,
    ...over,
  };
}

function event(type: string, data: Record<string, unknown>): StageEvent {
  return { type, data };
}

describe("whether a run said anything about stages", () => {
  it("is false for a run stored before the team was stages", () => {
    expect(hasStageRecord([], null)).toBe(false);
    expect(hasStageRecord([event("agent_message", {})], [])).toBe(false);
  });

  it("is true from the stored rollup alone", () => {
    expect(hasStageRecord([], [stored()])).toBe(true);
  });

  it("is true from a live event alone, before any report exists", () => {
    expect(hasStageRecord([event("stage_started", { stage: "triage" })], null)).toBe(true);
  });
});

describe("the timeline from the stored rollup", () => {
  it("reads a stage that ran as done and one that declined as skipped", () => {
    const rows = stageTimeline(null, [
      stored(),
      stored({ key: "apk", ran: false, reason: "condition not met", agents: ["apkscan"] }),
    ]);
    expect(rows.map((r) => [r.key, r.status])).toEqual([
      ["analysis", "done"],
      ["apk", "skipped"],
    ]);
  });

  it("gives a stage that declined without a reason one worth printing", () => {
    const [row] = stageTimeline(null, [stored({ ran: false, reason: "" })]);
    expect(row.reason).toBe("did not run");
  });

  it("keeps the declaration order, including the stages that never ran", () => {
    const rows = stageTimeline(null, [
      stored({ key: "triage" }),
      stored({ key: "static" }),
      stored({ key: "verdict" }),
    ]);
    expect(rows.map((r) => r.key)).toEqual(["triage", "static", "verdict"]);
  });
});

describe("the timeline from live events", () => {
  it("shows a stage that has started and not yet ended as running", () => {
    const rows = stageTimeline(
      [event("stage_started", { stage: "triage", kind: "analysis", agents: ["triage"] })],
      null
    );
    expect(rows).toEqual([
      {
        key: "triage",
        kind: "analysis",
        status: "running",
        reason: "",
        agents: ["triage"],
        duration_ms: 0,
      },
    ]);
  });

  it("closes a stage when its end arrives, with the duration it carried", () => {
    const rows = stageTimeline(
      [
        event("stage_started", { stage: "triage", kind: "analysis", agents: ["triage"] }),
        event("stage_finished", { stage: "triage", kind: "analysis", duration_ms: 1500 }),
      ],
      null
    );
    expect(rows[0].status).toBe("done");
    expect(rows[0].duration_ms).toBe(1500);
    expect(rows[0].agents).toEqual(["triage"]);
  });

  it("records a skip with the reason the condition gave", () => {
    const [row] = stageTimeline(
      [
        event("stage_skipped", {
          stage: "apk",
          kind: "analysis",
          reason: 'condition not met: extension == "apk"',
        }),
      ],
      null
    );
    expect(row.status).toBe("skipped");
    expect(row.reason).toBe('condition not met: extension == "apk"');
  });

  it("ignores every event that is not a stage event", () => {
    expect(stageTimeline([event("agent_message", { speaker: "static" })], null)).toEqual([]);
  });

  it("ignores a stage event with no stage on it", () => {
    expect(stageTimeline([event("stage_started", {})], null)).toEqual([]);
  });
});

describe("live events over the stored rollup", () => {
  it("keep the stages that have not happened yet and update the one that has", () => {
    const rows = stageTimeline(
      [event("stage_started", { stage: "verdict", kind: "verdict", agents: ["judge"] })],
      [stored({ key: "analysis" }), stored({ key: "verdict", kind: "verdict", ran: false })]
    );
    expect(rows.map((r) => [r.key, r.status])).toEqual([
      ["analysis", "done"],
      ["verdict", "running"],
    ]);
  });

  it("append a stage the rollup never mentioned", () => {
    const rows = stageTimeline(
      [event("stage_started", { stage: "reversing", kind: "analysis" })],
      [stored({ key: "analysis" })]
    );
    expect(rows.map((r) => r.key)).toEqual(["analysis", "reversing"]);
  });
});

describe("a stage's duration", () => {
  it("is nothing at all when the stage has not timed itself", () => {
    expect(formatStageDuration(0)).toBe("");
  });

  it("reads in the units the number deserves", () => {
    expect(formatStageDuration(120)).toBe("120 ms");
    expect(formatStageDuration(4_200)).toBe("4.2 s");
    expect(formatStageDuration(185_000)).toBe("3m 5s");
  });
});

describe("the tool calls each agent made", () => {
  it("are counted from the ledger, not from the findings", () => {
    expect(
      toolCallsByAgent([{ agent: "static" }, { agent: "static" }, { agent: "network" }])
    ).toEqual({ static: 2, network: 1 });
  });

  it("are none when the ledger could not be read", () => {
    expect(toolCallsByAgent(null)).toEqual({});
  });

  it("skip an entry with no agent on it rather than inventing one", () => {
    expect(toolCallsByAgent([{ agent: "" }])).toEqual({});
  });
});
