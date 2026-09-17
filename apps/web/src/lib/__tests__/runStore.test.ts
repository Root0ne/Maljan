import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  applyRunEvents,
  configureRunTransport,
  getRun,
  hydrateRunTranscript,
  resetRun,
  setRunRoster,
  setRunStoredStages,
  subscribeRun,
  type IncomingEvent,
  type RunSocketHandlers,
  type RunTransport,
} from "@/lib/runStore";

/**
 * The run store, driven through a transport the test owns.
 *
 * Every property worth holding here is a property of the store and not of the
 * browser: what order events end up in, which two copies of one event are the
 * same event, what cursor a resume asks from, and what survives a reader
 * leaving the page. The transport seam is what lets all four be asserted
 * without a socket.
 */

const JOB = "job-1";

interface Dial {
  since: number;
  handlers: RunSocketHandlers;
  closed: boolean;
}

function fakeTransport(feed: IncomingEvent[] = []) {
  const dials: Dial[] = [];
  const reads: (number | undefined)[] = [];
  const transport: RunTransport = {
    async readEvents(_jobId, since) {
      reads.push(since);
      return feed;
    },
    connect(_jobId, since, handlers) {
      const dial: Dial = { since, handlers, closed: false };
      dials.push(dial);
      return {
        close() {
          dial.closed = true;
        },
      };
    },
  };
  return { transport, dials, reads };
}

function event(type: string, data: Record<string, unknown> = {}): IncomingEvent {
  return { type, data, ts: "2026-09-17T10:00:00Z" };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  resetRun(JOB);
  configureRunTransport(null);
  vi.useRealTimers();
});

describe("ordering and identity", () => {
  it("holds events in sequence order however they arrive", () => {
    applyRunEvents(JOB, [
      event("agent_message", { seq: 3, text: "third" }),
      event("agent_message", { seq: 1, text: "first" }),
      event("agent_message", { seq: 2, text: "second" }),
    ]);

    expect(getRun(JOB).events.map((e) => e.data.text)).toEqual(["first", "second", "third"]);
    expect(getRun(JOB).lastSeq).toBe(3);
  });

  it("keeps one copy of an event however many times it is replayed", () => {
    applyRunEvents(JOB, [event("agent_message", { seq: 7, text: "once" })]);
    applyRunEvents(JOB, [event("agent_message", { seq: 7, text: "once" })]);
    applyRunEvents(JOB, [{ ...event("agent_message", { seq: 7, text: "once" }), stream_id: "1-0" }]);

    expect(getRun(JOB).events).toHaveLength(1);
  });

  it("orders a run that has no sequence numbers by arrival", () => {
    applyRunEvents(JOB, [
      event("agent_message", { text: "first" }),
      event("agent_message", { text: "second" }),
    ]);
    applyRunEvents(JOB, [event("agent_message", { text: "third" })]);

    expect(getRun(JOB).events.map((e) => e.data.text)).toEqual(["first", "second", "third"]);
    expect(getRun(JOB).lastSeq).toBe(0);
    expect(getRun(JOB).events.every((e) => e.seq === undefined)).toBe(true);
  });

  it("dedupes an unnumbered event on what it does carry", () => {
    applyRunEvents(JOB, [{ ...event("agent_message", { text: "same" }), stream_id: "5-0" }]);
    applyRunEvents(JOB, [{ ...event("agent_message", { text: "same" }), stream_id: "5-0" }]);
    applyRunEvents(JOB, [event("agent_message", { text: "same" })]);
    applyRunEvents(JOB, [event("agent_message", { text: "same" })]);

    expect(getRun(JOB).events).toHaveLength(2);
  });

  it("leaves an unnumbered line where it arrived among numbered ones", () => {
    /* The stored conversation of an older run numbers its rows from zero, and
     * zero means "no number" — so the first line of such a run arrives without
     * one while the rest carry the publisher's. It belongs at the front, where
     * it happened, not at the end. */
    applyRunEvents(JOB, [
      event("agent_message", { seq: 0, text: "opening" }),
      event("agent_message", { seq: 1, text: "answer" }),
      event("agent_message", { seq: 2, text: "verdict" }),
    ]);

    expect(getRun(JOB).events.map((e) => e.data.text)).toEqual([
      "opening",
      "answer",
      "verdict",
    ]);
  });

  it("drops the heartbeat, which is not part of the feed", () => {
    applyRunEvents(JOB, [event("heartbeat"), event("pong"), event("status_change", { seq: 1 })]);
    expect(getRun(JOB).events).toHaveLength(1);
  });
});

describe("the roster and the stages", () => {
  it("keeps the first roster it is given", () => {
    setRunRoster(JOB, { agents: [{ key: "ahmet", label: "Ahmet", role: "analyst", stages: ["a"] }], stages: [] });
    setRunRoster(JOB, { agents: [], stages: [] });

    expect(getRun(JOB).roster?.agents[0].label).toBe("Ahmet");
  });

  it("takes the roster the run announces when it has no other", () => {
    applyRunEvents(JOB, [
      event("roster", {
        seq: 1,
        agents: [{ key: "lead", label: "Lead analyst", role: "analyst", stages: ["analysis"] }],
        stages: [{ key: "analysis", label: "Analysis", kind: "analysis", agents: ["lead"] }],
      }),
    ]);

    expect(getRun(JOB).roster?.agents[0].label).toBe("Lead analyst");
    expect(getRun(JOB).roster?.stages[0].key).toBe("analysis");
  });

  it("keeps the roster the job carried over the one the run announces", () => {
    setRunRoster(JOB, {
      agents: [{ key: "lead", label: "From the job", role: "analyst", stages: [] }],
      stages: [],
    });
    applyRunEvents(JOB, [
      event("roster", { seq: 1, agents: [{ key: "lead", label: "From the feed", role: "analyst", stages: [] }], stages: [] }),
    ]);

    expect(getRun(JOB).roster?.agents[0].label).toBe("From the job");
  });

  it("lays live stage events over the stored rollup", () => {
    setRunStoredStages(JOB, [
      { key: "analysis", kind: "analysis", ran: true, reason: "", agents: [], duration_ms: 10 },
      { key: "debate", kind: "debate", ran: false, reason: "one analyst", agents: [], duration_ms: 0 },
    ]);
    applyRunEvents(JOB, [event("stage_started", { seq: 1, stage: "analysis", kind: "analysis" })]);

    const stages = getRun(JOB).stages;
    expect(stages.map((s) => [s.key, s.status])).toEqual([
      ["analysis", "running"],
      ["debate", "skipped"],
    ]);
    expect(stages[1].reason).toBe("one analyst");
  });
});

describe("the recorded conversation", () => {
  const ROWS = [
    { speaker: "static", role: "analyst", round: 0, status: "complete", text: "one claim" },
    { speaker: "judge", role: "judge", round: 1, status: "complete", text: "Verdict: Malware" },
  ];

  it("answers for a run whose feed predates the event recording", async () => {
    const { transport } = fakeTransport();
    configureRunTransport(transport);
    hydrateRunTranscript(JOB, ROWS);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    const events = getRun(JOB).events;
    expect(events).toHaveLength(2);
    expect(events[0].data.kind).toBe("says");
    expect(events[1].data.kind).toBe("verdict");
    /* Never numbered, whatever the rows carried: an older run numbered its
     * stored rows by position, and a position that looked like a publisher's
     * number would shadow the event actually holding it. */
    expect(events.every((e) => e.seq === undefined)).toBe(true);
  });

  it("stands down for a run that still has its feed", async () => {
    const { transport } = fakeTransport([event("agent_message", { seq: 1, text: "live" })]);
    configureRunTransport(transport);
    hydrateRunTranscript(JOB, ROWS);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(getRun(JOB).events.map((e) => e.data.text)).toEqual(["live"]);
  });

  it("waits for the feed to answer before standing in for it", () => {
    hydrateRunTranscript(JOB, ROWS);

    // Nothing has asked the endpoint yet, so nothing is known about the feed.
    expect(getRun(JOB).events).toEqual([]);
  });

  it("answers when the feed could not be read at all", async () => {
    configureRunTransport({
      async readEvents() {
        throw new Error("stream unavailable");
      },
      connect() {
        return { close() {} };
      },
    });
    hydrateRunTranscript(JOB, ROWS);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(getRun(JOB).events).toHaveLength(2);
    expect(getRun(JOB).feedError).toContain("stream unavailable");
  });
});

describe("the socket", () => {
  it("back-fills the whole run, then resumes from the last number held", async () => {
    const { transport, dials, reads } = fakeTransport([
      event("agent_message", { seq: 1, text: "first" }),
      event("agent_message", { seq: 2, text: "second" }),
    ]);
    configureRunTransport(transport);

    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(reads).toEqual([undefined]);
    expect(dials).toHaveLength(1);
    expect(dials[0].since).toBe(2);
    expect(getRun(JOB).events).toHaveLength(2);
  });

  it("merges what the socket replays with what the back-fill already held", async () => {
    const { transport, dials } = fakeTransport([event("agent_message", { seq: 1, text: "first" })]);
    configureRunTransport(transport);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    dials[0].handlers.onEvent(event("agent_message", { seq: 1, text: "first" }));
    dials[0].handlers.onEvent(event("agent_message", { seq: 2, text: "second" }));
    await vi.advanceTimersByTimeAsync(0);

    expect(getRun(JOB).events.map((e) => e.data.text)).toEqual(["first", "second"]);
  });

  it("asks the reconnect for everything after the last number it holds", async () => {
    const { transport, dials } = fakeTransport([event("agent_message", { seq: 4 })]);
    configureRunTransport(transport);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);
    dials[0].handlers.onOpen();
    dials[0].handlers.onEvent(event("agent_message", { seq: 9 }));
    await vi.advanceTimersByTimeAsync(0);

    dials[0].handlers.onClose(1006);
    await vi.advanceTimersByTimeAsync(31_000);

    expect(dials).toHaveLength(2);
    expect(dials[1].since).toBe(9);
  });

  it("does not redial after a rejected credential", async () => {
    const { transport, dials } = fakeTransport();
    configureRunTransport(transport);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    dials[0].handlers.onClose(4401);
    await vi.advanceTimersByTimeAsync(60_000);

    expect(dials).toHaveLength(1);
    expect(getRun(JOB).connection).toBe("unauthorized");
  });

  it("says so when the recorded feed cannot be read", async () => {
    configureRunTransport({
      async readEvents() {
        throw new Error("stream unavailable");
      },
      connect(_jobId, _since, handlers) {
        void handlers;
        return { close() {} };
      },
    });
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(getRun(JOB).feedError).toContain("stream unavailable");
  });

  it("survives a route change without re-reading the run", async () => {
    const { transport, dials, reads } = fakeTransport([event("agent_message", { seq: 1, text: "held" })]);
    configureRunTransport(transport);

    const leave = subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);
    leave();
    await vi.advanceTimersByTimeAsync(1_000);

    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(reads).toHaveLength(1);
    expect(dials).toHaveLength(1);
    expect(dials[0].closed).toBe(false);
    expect(getRun(JOB).events.map((e) => e.data.text)).toEqual(["held"]);
  });

  it("closes the socket once nobody has read the run for a while", async () => {
    const { transport, dials } = fakeTransport();
    configureRunTransport(transport);
    const leave = subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    leave();
    await vi.advanceTimersByTimeAsync(31_000);

    expect(dials[0].closed).toBe(true);
    expect(getRun(JOB).connection).toBe("closed");
  });

  it("tells its readers when something arrives", async () => {
    const { transport, dials } = fakeTransport();
    configureRunTransport(transport);
    let notifications = 0;
    subscribeRun(JOB, () => {
      notifications += 1;
    });
    await vi.advanceTimersByTimeAsync(0);
    const before = notifications;

    dials[0].handlers.onEvent(event("agent_message", { seq: 1 }));
    await vi.advanceTimersByTimeAsync(0);

    expect(notifications).toBeGreaterThan(before);
  });

  it("commits a burst of frames once", async () => {
    /* A resume arrives one frame at a time. Folding and publishing each one
     * separately is what made a long replay freeze the page it opened in. */
    const { transport, dials } = fakeTransport();
    configureRunTransport(transport);
    let notifications = 0;
    subscribeRun(JOB, () => {
      notifications += 1;
    });
    await vi.advanceTimersByTimeAsync(0);
    const before = notifications;

    for (let seq = 1; seq <= 200; seq += 1) {
      dials[0].handlers.onEvent(event("agent_message", { seq, text: `line ${seq}` }));
    }
    await vi.advanceTimersByTimeAsync(0);

    expect(getRun(JOB).events).toHaveLength(200);
    expect(notifications - before).toBe(1);
  });
});
