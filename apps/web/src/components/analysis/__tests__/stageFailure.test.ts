import { describe, expect, it } from "vitest";

import type { StageRow } from "../pipelineSteps";
import { stageTimeline, type StageEvent } from "../stageTimeline";

function stored(over: Partial<StageRow> = {}): StageRow {
  return {
    key: "triage",
    kind: "pack",
    ran: true,
    reason: "",
    agents: [],
    duration_ms: 1200,
    ...over,
  } as StageRow;
}

const event = (type: string, data: Record<string, unknown>): StageEvent => ({ type, data });

describe("a stage that ran and went wrong", () => {
  it("is drawn failed with its reason, not DONE, from the stored rollup", () => {
    const [row] = stageTimeline([], [stored({ failure: true, reason: "the pack crashed" })]);
    expect(row.status).toBe("failed");
    expect(row.reason).toBe("the pack crashed");
  });

  it("still says it failed when the rollup gave no reason", () => {
    const [row] = stageTimeline([], [stored({ failure: true, reason: "" })]);
    expect(row.status).toBe("failed");
    expect(row.reason).toBe("the stage failed");
  });

  it("is failed from a live finish that carries a reason, which only a failure does", () => {
    const [row] = stageTimeline(
      [event("stage_started", { stage: "triage" }), event("stage_finished", { stage: "triage", reason: "timed out" })],
      null,
    );
    expect(row.status).toBe("failed");
    expect(row.reason).toBe("timed out");
  });

  it("stays failed under a replayed finish that says nothing", () => {
    const [row] = stageTimeline(
      [event("stage_finished", { stage: "triage", reason: "" })],
      [stored({ failure: true, reason: "the pack crashed" })],
    );
    expect(row.status).toBe("failed");
    expect(row.reason).toBe("the pack crashed");
  });

  it("leaves a clean finish DONE", () => {
    const [row] = stageTimeline([event("stage_finished", { stage: "triage", reason: "" })], [stored()]);
    expect(row.status).toBe("done");
    expect(row.reason).toBe("");
  });

  it("reads an explicit failure flag on the event either way", () => {
    expect(
      stageTimeline([event("stage_finished", { stage: "triage", failure: true })], null)[0].status,
    ).toBe("failed");
    expect(
      stageTimeline([event("stage_finished", { stage: "triage", failure: false, reason: "x" })], null)[0]
        .status,
    ).toBe("done");
  });
});
