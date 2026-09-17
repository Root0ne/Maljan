import { describe, expect, it } from "vitest";
import { messagesFromEvents, messagesFromTranscript } from "../transcript";
import type { WSEvent } from "@/types";

const say = (data: Record<string, unknown>, ts = "2026-09-17T08:00:00Z"): WSEvent => ({
  type: "agent_message",
  data,
  ts,
});

describe("an addressed line in the transcript", () => {
  it("keeps the addressee and the stage from a live event", () => {
    const [ask] = messagesFromEvents([
      say({ speaker: "lead", role: "analyst", round: 0, text: "Does it beacon?", addressed_to: "network", stage: "lead" }),
    ]);
    expect(ask.addressedTo).toBe("network");
    expect(ask.stage).toBe("lead");
  });

  it("does not collapse two asks of the same specialist into one line", () => {
    const messages = messagesFromEvents([
      say({ speaker: "lead", role: "analyst", round: 0, text: "first", addressed_to: "static" }),
      say({ speaker: "static", role: "analyst", round: 0, text: "answer one", addressed_to: "lead" }),
      say({ speaker: "lead", role: "analyst", round: 0, text: "second", addressed_to: "static" }),
      say({ speaker: "static", role: "analyst", round: 0, text: "answer two", addressed_to: "lead" }),
      say({ speaker: "lead", role: "analyst", round: 0, text: "my report" }),
    ]);
    expect(messages.map((m) => m.text)).toEqual([
      "first",
      "answer one",
      "second",
      "answer two",
      "my report",
    ]);
    expect(new Set(messages.map((m) => m.id)).size).toBe(5);
  });

  it("still drops a line said to the room that arrives twice", () => {
    const twice = say({ speaker: "static", role: "analyst", round: 0, text: "report" });
    expect(messagesFromEvents([twice, twice])).toHaveLength(1);
  });

  it("keeps one line when the back-fill and the live socket both carry it", () => {
    const twice = say({
      speaker: "lead",
      role: "analyst",
      round: 0,
      text: "Does it beacon?",
      addressed_to: "network",
    });
    expect(messagesFromEvents([twice, twice])).toHaveLength(1);
  });

  it("reads the same fields off a recorded row", () => {
    const [row] = messagesFromTranscript([
      {
        seq: 3,
        speaker: "static",
        role: "analyst",
        round: 1,
        status: "complete",
        text: "answer",
        addressed_to: "lead",
        stage: "lead",
      },
    ]);
    expect(row.addressedTo).toBe("lead");
    expect(row.stage).toBe("lead");
    // A recorded row and its live twin are the same line, so a job whose
    // events have not yet expired does not draw the ask twice.
    const [live] = messagesFromEvents([
      say({ speaker: "static", role: "analyst", round: 1, text: "answer", addressed_to: "lead" }),
    ]);
    expect(row.id).toBe(live.id);
  });

  it("gives every row of a delegated round an id of its own", () => {
    /* `addressed_to` has no column, so a lead's report and each of its asks
     * come back under one identity. React keys them, and a merge tells them
     * apart, so the recording's own order is what separates them. */
    const rows = messagesFromTranscript([
      { seq: 1, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "first" },
      { seq: 2, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "second" },
      { seq: 3, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "my report" },
    ]);
    expect(new Set(rows.map((m) => m.id)).size).toBe(3);
    expect(rows.map((m) => m.id)).toEqual([
      "analyst:lead:0#1",
      "analyst:lead:0#2",
      "analyst:lead:0#3",
    ]);
  });

  it("leaves a row that is already alone identified the way a live event is", () => {
    const [row] = messagesFromTranscript([
      { seq: 4, speaker: "static", role: "analyst", round: 0, status: "complete", text: "report" },
    ]);
    expect(row.id).toBe("analyst:static:0");
  });
});
