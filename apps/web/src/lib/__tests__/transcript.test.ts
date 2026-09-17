import { describe, expect, it } from "vitest";
import {
  mergeTranscripts,
  messagesFromEvents,
  messagesFromTranscript,
} from "../transcript";
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
    // events have not yet expired does not draw the ask twice. They are the
    // same by construction now: the publisher numbers the message once and
    // the stored row is written with that same number.
    const [live] = messagesFromEvents([
      say({
        seq: 3,
        speaker: "static",
        role: "analyst",
        round: 1,
        text: "answer",
        addressed_to: "lead",
      }),
    ]);
    expect(row.id).toBe(live.id);
    expect(row.seq).toBe(3);
  });

  it("falls back to the derived id for a run recorded before there were numbers", () => {
    /* Nothing published a `seq` then, so what a live event and its stored row
     * still had in common is who spoke, when, and what they said. The API
     * sends `null` for every row of such a run — its old column held the
     * message's position within the report, a different number from the same
     * run's live events — and every row falls back, not only the first. */
    const rows = messagesFromTranscript([
      { seq: null, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "one" },
      { seq: null, speaker: "static", role: "analyst", round: 0, status: "complete", text: "two" },
      { seq: null, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "three" },
    ]);
    const live = messagesFromEvents([
      say({ speaker: "lead", role: "analyst", round: 0, text: "one" }),
      say({ speaker: "static", role: "analyst", round: 0, text: "two" }),
      say({ speaker: "lead", role: "analyst", round: 0, text: "three" }),
    ]);
    for (const row of rows) {
      expect(row.id).not.toContain("seq:");
      expect(row.seq).toBeUndefined();
    }
    expect(rows.map((m) => m.id).sort()).toEqual(live.map((m) => m.id).sort());
    // The whole point: merged, a legacy run is drawn once, not twice.
    expect(mergeTranscripts(rows, live)).toHaveLength(3);
  });

  it("treats a missing seq the same as a null one", () => {
    const [row] = messagesFromTranscript([
      { speaker: "static", role: "analyst", round: 1, status: "complete", text: "answer" },
    ]);
    const [live] = messagesFromEvents([
      say({ speaker: "static", role: "analyst", round: 1, text: "answer" }),
    ]);
    expect(row.seq).toBeUndefined();
    expect(row.id).toBe(live.id);
  });

  it("never reads a legacy position as a publisher number", () => {
    /* The defect this rule exists for: the old column was
     * `enumerate(transcript)` — 0, 1, 2, … — so rows 1..n of every
     * pre-release report looked like publisher numbers and were drawn twice
     * beside their still-live twins. The API now sends null for that run, so
     * there is nothing here that could be mistaken for one. */
    const rows = messagesFromTranscript([
      { seq: null, speaker: "a", role: "analyst", round: 0, status: "complete", text: "one" },
      { seq: null, speaker: "b", role: "analyst", round: 0, status: "complete", text: "two" },
    ]);
    expect(rows.every((m) => !m.id.startsWith("seq:"))).toBe(true);
  });

  it("gives every row of a delegated round an id of its own", () => {
    /* A lead's report and each of its asks are said by the same speaker in
     * the same round; the number the publisher gave each one is what tells
     * them apart, and the live copy carries the same number. */
    const rows = messagesFromTranscript([
      { seq: 1, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "first" },
      { seq: 2, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "second" },
      { seq: 3, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "my report" },
    ]);
    expect(new Set(rows.map((m) => m.id)).size).toBe(3);
  });

  it("separates two rows that said the same thing by their recorded order", () => {
    const twice = { speaker: "lead", role: "analyst", round: 0, status: "complete", text: "again" };
    const rows = messagesFromTranscript([
      { seq: 1, ...twice },
      { seq: 2, ...twice },
    ]);
    expect(new Set(rows.map((m) => m.id)).size).toBe(2);
  });

  it("draws a delegated round once when a report and its events both exist", () => {
    /* One number, assigned once, carried by both copies: the merge collapses
     * them however differently they were worded or capped on the way. */
    const events = messagesFromEvents([
      say({
        seq: 1,
        speaker: "lead",
        role: "analyst",
        round: 0,
        text: "ask one",
        addressed_to: "static",
      }),
      say({
        seq: 2,
        speaker: "static",
        role: "analyst",
        round: 0,
        text: "answer",
        addressed_to: "lead",
      }),
      say({ seq: 3, speaker: "lead", role: "analyst", round: 0, text: "my report" }),
    ]);
    const persisted = messagesFromTranscript([
      { seq: 1, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "ask one" },
      { seq: 2, speaker: "static", role: "analyst", round: 0, status: "complete", text: "answer" },
      { seq: 3, speaker: "lead", role: "analyst", round: 0, status: "complete", text: "my report" },
    ]);

    const merged = mergeTranscripts(persisted, events);

    expect(merged).toHaveLength(3);
    expect(merged.map((m) => m.text)).toEqual(["ask one", "answer", "my report"]);
    // The arrow survives the merge: it is on the live copy and nothing on the
    // stored one overwrites it with undefined.
    expect(merged[0].addressedTo).toBe("static");
  });
});
