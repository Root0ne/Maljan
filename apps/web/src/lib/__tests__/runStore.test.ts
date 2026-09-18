import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  applyRunEvents,
  BACKFILL_LIMIT,
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
import { buildConversation, resetConversationCache } from "@/lib/conversation";
import type { JobRoster } from "@/types";

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

  it("stands in when the feed answered with everything but the talking", async () => {
    /* A run whose speech was never recorded as events still published its
     * roster, its stages and its tool calls. Reading "there are events" as
     * "there is a conversation" left that run with a stream of tool rows and
     * no argument behind them. */
    const { transport } = fakeTransport([
      event("roster", { seq: 1, agents: [], stages: [] }),
      event("stage_started", { seq: 2, stage: "analysis", kind: "analysis" }),
      event("tool_call_finished", { seq: 3, agent: "static", tool: "capa", ok: true }),
    ]);
    configureRunTransport(transport);
    hydrateRunTranscript(JOB, ROWS);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    const texts = getRun(JOB)
      .events.filter((e) => e.type === "agent_message")
      .map((e) => e.data.text);
    expect(texts).toEqual(["one claim", "Verdict: Malware"]);
  });

  it("draws a stored watcher as a notice, not as a member of the team", async () => {
    const { transport } = fakeTransport();
    configureRunTransport(transport);
    hydrateRunTranscript(JOB, [
      { speaker: "pipeline", role: "negotiator", round: 1, status: "complete", text: "Mediator: all agree." },
    ]);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(getRun(JOB).events[0].data.kind).toBe("system");
  });

  it("prefers the kind, the stage and the label the run recorded", async () => {
    /* A run recorded after those three became columns says what each line
     * was, where it was said and what its speaker was called. Deriving any of
     * them from a row that states them is how a delegated ask came back as a
     * plain line. */
    const { transport } = fakeTransport();
    configureRunTransport(transport);
    hydrateRunTranscript(JOB, [
      {
        speaker: "lead",
        role: "analyst",
        round: 0,
        status: "complete",
        text: "check the imports",
        kind: "delegation_ask",
        stage: "analysis",
        addressed_to: "ahmet",
        display_name: "Lead analyst",
      },
    ]);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    const data = getRun(JOB).events[0].data;
    expect(data.kind).toBe("delegation_ask");
    expect(data.stage).toBe("analysis");
    expect(data.display_name).toBe("Lead analyst");
    expect(data.addressed_to).toBe("ahmet");
  });

  it("derives the kind for a row that never recorded one", async () => {
    /* The fallback the older rows still need, kept exactly as it was. */
    const { transport } = fakeTransport();
    configureRunTransport(transport);
    hydrateRunTranscript(JOB, ROWS);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(getRun(JOB).events.map((e) => e.data.kind)).toEqual(["says", "verdict"]);
  });

  it("derives the kind when the row records one this view cannot draw", async () => {
    const { transport } = fakeTransport();
    configureRunTransport(transport);
    hydrateRunTranscript(JOB, [
      { speaker: "judge", role: "judge", round: 1, status: "complete", text: "Malware", kind: "semaphore" },
    ]);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(getRun(JOB).events[0].data.kind).toBe("verdict");
  });

  it("replays a recorded run into stages with its delegation arrows intact", async () => {
    /* The whole point of storing the three fields: a replayed conversation
     * and a live one are the same conversation. Grouped by the stage each
     * line was said in, and with the ask and its answer still pointing at
     * each other by name. */
    const roster: JobRoster = {
      agents: [
        { key: "lead", label: "Lead analyst", role: "analyst", stages: ["analysis"] },
        { key: "ahmet", label: "Ahmet", role: "analyst", stages: [], via: ["lead"] },
        { key: "judge", label: "Judge", role: "judge", stages: ["verdict"] },
      ],
      stages: [
        { key: "analysis", label: "Analysis", kind: "analysis", agents: ["lead"] },
        { key: "verdict", label: "Verdict", kind: "verdict", agents: ["judge"] },
      ],
    };
    const { transport } = fakeTransport();
    configureRunTransport(transport);
    resetConversationCache();
    setRunRoster(JOB, roster);
    hydrateRunTranscript(JOB, [
      { speaker: "lead", role: "analyst", round: 0, status: "complete", text: "check the imports", kind: "delegation_ask", stage: "analysis", addressed_to: "ahmet", display_name: "Lead analyst" },
      { speaker: "ahmet", role: "analyst", round: 0, status: "complete", text: "two suspicious imports", kind: "delegation_answer", stage: "analysis", addressed_to: "lead", display_name: "Ahmet" },
      { speaker: "judge", role: "judge", round: 1, status: "complete", text: "Malware", kind: "verdict", stage: "verdict", display_name: "Judge" },
    ]);
    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    const run = getRun(JOB);
    const conversation = buildConversation(run.events, run.roster);
    expect(conversation.stages.map((s) => s.key)).toEqual(["analysis", "verdict"]);
    const analysis = conversation.stages[0].rounds.flatMap((r) => r.items);
    expect(analysis.map((i) => i.kind)).toEqual(["delegation_ask", "delegation_answer"]);
    expect(analysis[0].addressedToName).toBe("Ahmet");
    expect(analysis[1].addressedToName).toBe("Lead analyst");
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

describe("the back-fill", () => {
  /** A recorded feed served the way the endpoint serves it: one capped page
   *  per read, from the cursor the caller asked with. */
  function pagingTransport(feed: IncomingEvent[]) {
    const reads: (number | undefined)[] = [];
    const transport: RunTransport = {
      async readEvents(_jobId, since) {
        reads.push(since);
        const from = since === undefined ? 0 : since;
        return feed.filter((e) => Number(e.data?.seq) > from).slice(0, BACKFILL_LIMIT);
      },
      connect() {
        return { close() {} };
      },
    };
    return { transport, reads };
  }

  function recorded(count: number): IncomingEvent[] {
    return Array.from({ length: count }, (_, i) =>
      event("agent_message", { seq: i + 1, text: `line ${i + 1}` }),
    );
  }

  it("reads a run longer than one page, in order, to its last event", async () => {
    const { transport, reads } = pagingTransport(recorded(2500));
    configureRunTransport(transport);

    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(reads).toEqual([undefined, 1000, 2000]);
    const events = getRun(JOB).events;
    expect(events).toHaveLength(2500);
    expect(events.map((e) => e.seq)).toEqual(events.map((_, i) => i + 1));
    expect(getRun(JOB).lastSeq).toBe(2500);
    expect(getRun(JOB).feedError).toBeNull();
  });

  it("stops on a page that does not advance, and says the run is cut short", async () => {
    const page = recorded(BACKFILL_LIMIT);
    let reads = 0;
    configureRunTransport({
      async readEvents() {
        reads += 1;
        return page;
      },
      connect() {
        return { close() {} };
      },
    });

    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(reads).toBe(2);
    expect(getRun(JOB).events).toHaveLength(BACKFILL_LIMIT);
    expect(getRun(JOB).feedError).toContain("only part of this run");
  });

  it("keeps one copy of an event that arrives while a page is in flight", async () => {
    /* The run is still being published while its recording is read. A frame
     * committed between two pages is the same event the next page carries,
     * and the page after it must still be asked for from the recording's own
     * cursor rather than from the number the live frame brought. */
    const feed = recorded(1500);
    const { transport, reads } = pagingTransport(feed);
    let pagesRead = 0;
    configureRunTransport({
      async readEvents(jobId, since) {
        pagesRead += 1;
        if (pagesRead === 1) {
          const page = await transport.readEvents(jobId, since);
          applyRunEvents(JOB, [event("agent_message", { seq: 1200, text: "line 1200" })]);
          return page;
        }
        return transport.readEvents(jobId, since);
      },
      connect() {
        return { close() {} };
      },
    });

    subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);

    expect(reads).toEqual([undefined, 1000]);
    const events = getRun(JOB).events;
    expect(events).toHaveLength(1500);
    expect(events.filter((e) => e.seq === 1200)).toHaveLength(1);
    expect(events.map((e) => e.seq)).toEqual(events.map((_, i) => i + 1));
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

  it("does not redial a refused credential for a second reader", async () => {
    /* Two readers of one run arrive together — the analysis layout and the tab
     * inside it — and each asks the feed to open. The second answers from the
     * back-fill already made and dials first, so the first reader's dial lands
     * after the socket has been refused. It must not dial. */
    let release = () => {};
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const dials: number[] = [];
    configureRunTransport({
      async readEvents() {
        await held;
        return [];
      },
      connect(_jobId, _since, handlers) {
        dials.push(1);
        // What the server does with a rejected credential: refuses it. The
        // close arrives after the dial returns, as a socket's does.
        queueMicrotask(() => handlers.onClose(4401));
        return { close() {} };
      },
    });

    subscribeRun(JOB, () => {});
    subscribeRun(JOB, () => {});
    // The second reader's back-fill answers from cache, so it dials and is
    // refused while the first reader's read is still in flight.
    await vi.advanceTimersByTimeAsync(0);
    expect(dials).toHaveLength(1);
    expect(getRun(JOB).connection).toBe("unauthorized");

    release();
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
