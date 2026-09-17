import { afterEach, describe, expect, it, vi } from "vitest";

import {
  buildConversation,
  resetConversationCache,
  toolCallsFromFeed,
} from "@/lib/conversation";
import {
  applyRunEvents,
  configureRunTransport,
  getRun,
  resetRun,
  subscribeRun,
  type IncomingEvent,
  type RunSocketHandlers,
  type RunTransport,
} from "@/lib/runStore";
import type { JobRoster } from "@/types";

/**
 * A long run, at the size that made the page freeze.
 *
 * A run whose feed is longer than one back-fill is replayed by the socket a
 * frame at a time, so the console used to fold, copy and rebuild the whole
 * conversation three thousand times in a row. These are the two properties
 * that fixed it, asserted rather than asserted-about: a burst of frames is
 * one commit, and a continued walk keeps the item objects it already made, so
 * a memoised row does not redraw because somebody else spoke.
 *
 * The time bounds are deliberately loose. They are there to catch a return to
 * quadratic work on a loaded machine, not to measure this one.
 */

const JOB = "job-scale";
const SIZE = 3000;

const ROSTER: JobRoster = {
  agents: [
    { key: "lead", label: "Lead analyst", role: "analyst", stages: ["analysis"] },
    { key: "ahmet", label: "Ahmet", role: "analyst", stages: ["analysis"] },
    { key: "judge", label: "Judge", role: "judge", stages: ["verdict"] },
  ],
  stages: [
    { key: "analysis", label: "Analysis", kind: "analysis", agents: ["lead", "ahmet"] },
    { key: "verdict", label: "Verdict", kind: "verdict", agents: ["judge"] },
  ],
};

/** A run of the shape a long analysis really publishes: mostly tool calls,
 *  with messages, corrections and streamed turns between them. */
function longRun(): IncomingEvent[] {
  const events: IncomingEvent[] = [
    { type: "roster", data: { seq: 1, ...ROSTER }, ts: "" },
    { type: "stage_started", data: { seq: 2, stage: "analysis", kind: "analysis" }, ts: "" },
  ];
  let seq = 2;
  const next = () => (seq += 1);
  while (events.length < SIZE) {
    const agent = events.length % 2 === 0 ? "lead" : "ahmet";
    const tool = `tool_${events.length % 7}`;
    events.push({
      type: "tool_call_started",
      data: { seq: next(), stage: "analysis", agent, tool, args_summary: "read" },
      ts: "",
    });
    events.push({
      type: "tool_call_finished",
      data: {
        seq: next(),
        stage: "analysis",
        agent,
        tool,
        evidence_id: `ev_${events.length}`,
        ok: true,
        duration_ms: 12,
        summary: "answered",
      },
      ts: "",
    });
    events.push({
      type: "agent_message_delta",
      data: { seq: next(), stage: "analysis", agent, text_delta: "thinking " },
      ts: "",
    });
    events.push({
      type: "agent_message",
      data: {
        seq: next(),
        stage: "analysis",
        speaker: agent,
        role: "analyst",
        round: 0,
        status: "complete",
        text: "one claim from the static layer",
      },
      ts: "",
    });
    events.push({
      type: "validation_feedback",
      data: {
        seq: next(),
        stage: "analysis",
        agent,
        code: "claim_without_evidence",
        message: "cite the call",
        retry_index: 1,
      },
      ts: "",
    });
  }
  return events.slice(0, SIZE);
}

function fakeTransport() {
  const dials: { handlers: RunSocketHandlers }[] = [];
  const transport: RunTransport = {
    async readEvents() {
      return [];
    },
    connect(_jobId, _since, handlers) {
      dials.push({ handlers });
      return { close() {} };
    },
  };
  return { transport, dials };
}

afterEach(() => {
  resetRun(JOB);
  resetConversationCache();
  configureRunTransport(null);
  vi.useRealTimers();
});

describe("a three-thousand-event run", () => {
  it("builds the whole conversation in one pass, bounded", () => {
    applyRunEvents(JOB, longRun());
    const events = getRun(JOB).events;
    expect(events).toHaveLength(SIZE);

    const started = performance.now();
    const conversation = buildConversation(events, ROSTER);
    const elapsed = performance.now() - started;

    expect(conversation.stages[0].rounds[0].items.length).toBeGreaterThan(1000);
    expect(elapsed).toBeLessThan(1000);
  });

  it("continues the walk instead of repeating it", () => {
    const all = longRun();
    applyRunEvents(JOB, all.slice(0, SIZE - 200));
    const first = getRun(JOB).events;
    buildConversation(first, ROSTER);

    /* Two hundred more frames, one commit at a time, which is what a resume
     * looks like. A walk that started again each time is the thing this
     * bound catches. */
    const started = performance.now();
    for (let i = SIZE - 200; i < SIZE; i += 1) {
      applyRunEvents(JOB, [all[i]]);
      buildConversation(getRun(JOB).events, ROSTER);
    }
    const elapsed = performance.now() - started;

    expect(getRun(JOB).events).toHaveLength(SIZE);
    expect(elapsed).toBeLessThan(1000);
  });

  it("keeps the items a reader is already looking at", () => {
    const all = longRun();
    applyRunEvents(JOB, all.slice(0, SIZE - 1));
    const before = buildConversation(getRun(JOB).events, ROSTER);
    const firstItem = before.stages[0].rounds[0].items[0];

    applyRunEvents(JOB, [all[SIZE - 1]]);
    const after = buildConversation(getRun(JOB).events, ROSTER);

    // Same object, so a memoised row does not redraw for somebody else's line.
    expect(after.stages[0].rounds[0].items[0]).toBe(firstItem);
    expect(after).not.toBe(before);
  });

  it("answers the same array with the same conversation", () => {
    applyRunEvents(JOB, longRun());
    const events = getRun(JOB).events;

    expect(buildConversation(events, ROSTER)).toBe(buildConversation(events, ROSTER));
    expect(toolCallsFromFeed(events)).toBe(toolCallsFromFeed(events));
  });

  it("commits a resume as a handful of batches, not three thousand", async () => {
    vi.useFakeTimers();
    const { transport, dials } = fakeTransport();
    configureRunTransport(transport);
    let commits = 0;
    subscribeRun(JOB, () => {
      commits += 1;
    });
    await vi.advanceTimersByTimeAsync(0);
    const before = commits;

    for (const event of longRun()) dials[0].handlers.onEvent(event);
    await vi.advanceTimersByTimeAsync(0);

    expect(getRun(JOB).events).toHaveLength(SIZE);
    expect(commits - before).toBe(1);
  });
});
