import { describe, expect, it } from "vitest";

import {
  buildConversation,
  filterConversation,
  groupOf,
  toolCallsFromFeed,
  type ConversationStage,
} from "@/lib/conversation";
import type { RunEvent } from "@/lib/runStore";
import type { JobRoster } from "@/types";

/**
 * Turning a feed into a conversation.
 *
 * The rules under test are the ones a reader would notice if they broke: a
 * line filed under the wrong stage, a tool result that never finds the call it
 * closes, a streamed turn left standing beside the finished message that
 * replaced it, and an agent drawn by its registry key when its operator gave
 * it a name.
 */

let seq = 0;
function event(type: string, data: Record<string, unknown> = {}): RunEvent {
  seq += 1;
  return { type, data, ts: "2026-09-17T10:00:00Z", seq, order: seq, sortKey: seq };
}

function unnumbered(type: string, data: Record<string, unknown> = {}): RunEvent {
  seq += 1;
  return { type, data, ts: "", order: seq, sortKey: seq / 1e9 };
}

const ROSTER: JobRoster = {
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

function itemsOf(stages: ConversationStage[]): string[] {
  return stages.flatMap((stage) =>
    stage.rounds.flatMap((round) => round.items.map((item) => `${stage.key}/${round.round}/${item.kind}`)),
  );
}

describe("grouping", () => {
  it("files every line under the stage and round it was said in", () => {
    const { stages } = buildConversation(
      [
        event("stage_started", { stage: "analysis", kind: "analysis" }),
        event("agent_message", { stage: "analysis", speaker: "lead", round: 0, text: "opening" }),
        event("agent_message", { stage: "analysis", speaker: "lead", round: 1, text: "revised" }),
        event("stage_finished", { stage: "analysis", duration_ms: 2400 }),
        event("stage_started", { stage: "verdict", kind: "verdict" }),
        event("agent_message", { stage: "verdict", speaker: "judge", round: 0, kind: "verdict", text: "Malware" }),
      ],
      ROSTER,
    );

    expect(stages.map((s) => [s.key, s.label, s.state])).toEqual([
      ["analysis", "Analysis", "done"],
      ["verdict", "Verdict", "running"],
    ]);
    expect(stages[0].durationMs).toBe(2400);
    expect(itemsOf(stages)).toEqual([
      "analysis/0/says",
      "analysis/1/says",
      "verdict/0/verdict",
    ]);
  });

  it("keeps a skipped stage and the reason it gave", () => {
    const { stages } = buildConversation(
      [event("stage_skipped", { stage: "debate", kind: "debate", reason: "one analyst" })],
      null,
    );

    expect(stages[0].state).toBe("skipped");
    expect(stages[0].reason).toBe("one analyst");
    expect(stages[0].rounds).toEqual([]);
  });

  it("gives a run that never named a stage one room", () => {
    const { stages } = buildConversation(
      [
        unnumbered("agent_message", { speaker: "static", round: 0, text: "first" }),
        unnumbered("agent_message", { speaker: "judge", round: 0, kind: "verdict", text: "Malware" }),
      ],
      null,
    );

    expect(stages).toHaveLength(1);
    expect(stages[0].key).toBe("");
    expect(stages[0].rounds[0].items.map((i) => i.text)).toEqual(["first", "Malware"]);
  });
});

describe("kinds", () => {
  it("draws a tool call and its result as one row", () => {
    const { stages } = buildConversation(
      [
        event("tool_call_started", { stage: "analysis", agent: "lead", tool: "afl", server: "r2", args_summary: "afl" }),
        event("tool_call_finished", {
          stage: "analysis",
          agent: "lead",
          tool: "afl",
          server: "r2",
          evidence_id: "ev_0007",
          ok: true,
          duration_ms: 812,
          summary: "41 functions",
        }),
      ],
      ROSTER,
    );

    const items = stages[0].rounds[0].items;
    expect(items).toHaveLength(1);
    expect(items[0].kind).toBe("tool_call");
    expect(items[0].tool).toMatchObject({
      name: "afl",
      server: "r2",
      evidenceId: "ev_0007",
      ok: true,
      durationMs: 812,
    });
    expect(items[0].text).toBe("41 functions");
  });

  it("leaves a call that has not answered marked as running", () => {
    const { stages } = buildConversation(
      [event("tool_call_started", { stage: "analysis", agent: "lead", tool: "afl" })],
      ROSTER,
    );

    expect(stages[0].rounds[0].items[0].tool?.ok).toBeNull();
  });

  it("pairs two calls of one tool in the order they were made", () => {
    const { stages } = buildConversation(
      [
        event("tool_call_started", { stage: "a", agent: "lead", tool: "afl", args_summary: "one" }),
        event("tool_call_started", { stage: "a", agent: "lead", tool: "afl", args_summary: "two" }),
        event("tool_call_finished", { stage: "a", agent: "lead", tool: "afl", evidence_id: "ev_1", ok: true }),
        event("tool_call_finished", { stage: "a", agent: "lead", tool: "afl", evidence_id: "ev_2", ok: false }),
      ],
      null,
    );

    const items = stages[0].rounds[0].items;
    expect(items.map((i) => i.tool?.evidenceId)).toEqual(["ev_1", "ev_2"]);
    expect(items.map((i) => i.tool?.ok)).toEqual([true, false]);
  });

  it("draws a result whose start it never saw", () => {
    const { stages } = buildConversation(
      [event("tool_call_finished", { stage: "a", agent: "lead", tool: "afl", evidence_id: "ev_9", ok: true })],
      null,
    );

    expect(stages[0].rounds[0].items[0].tool?.evidenceId).toBe("ev_9");
  });

  it("maps the notices, the question and the delegated pair onto their own kinds", () => {
    const { stages } = buildConversation(
      [
        event("validation_feedback", { stage: "a", agent: "lead", code: "no_evidence", message: "cite a call", retry_index: 1 }),
        event("judge_question", { stage: "a", text: "which call shows that", addressed_to: "lead" }),
        event("agent_message", { stage: "a", speaker: "lead", kind: "delegation_ask", addressed_to: "ahmet", text: "check the imports" }),
        event("agent_message", { stage: "a", speaker: "ahmet", kind: "delegation_answer", addressed_to: "lead", text: "two suspicious imports" }),
      ],
      ROSTER,
    );

    const items = stages[0].rounds[0].items;
    expect(items.map((i) => i.kind)).toEqual([
      "validation_feedback",
      "judge_question",
      "delegation_ask",
      "delegation_answer",
    ]);
    expect(items[0].code).toBe("no_evidence");
    expect(items[0].retryIndex).toBe(1);
    expect(items[1].addressedToName).toBe("Lead analyst");
    expect(items[2].addressedToName).toBe("Ahmet");
    expect(items.map((i) => groupOf(i.kind))).toEqual(["notices", "says", "says", "says"]);
  });

  it("reads an unknown kind as something said, rather than dropping the line", () => {
    const { stages } = buildConversation(
      [event("agent_message", { stage: "a", speaker: "lead", kind: "soliloquy", text: "hm" })],
      null,
    );

    expect(stages[0].rounds[0].items[0].kind).toBe("says");
  });
});

describe("one violation, one line", () => {
  function feedback(data: Record<string, unknown>) {
    return event("validation_feedback", {
      stage: "a",
      agent: "lead",
      code: "no_evidence",
      message: "cite a call",
      retry_index: 1,
      ...data,
    });
  }

  it("folds what the agent was told and how it ended into the first line's place", () => {
    const { stages } = buildConversation(
      [
        feedback({ state: "retried", path: "static.claims[2]" }),
        event("agent_message", { stage: "a", speaker: "lead", text: "revised" }),
        feedback({ state: "resolved", path: "static.claims[2]", message: "cite a call" }),
      ],
      ROSTER,
    );

    const items = stages[0].rounds[0].items;
    expect(items.map((i) => i.kind)).toEqual(["validation_feedback", "says"]);
    expect(items[0].feedback?.map((f) => f.state)).toEqual(["retried", "resolved"]);
    expect(items[0].path).toBe("static.claims[2]");
  });

  it("keeps two violations of one code on different claims apart", () => {
    const { stages } = buildConversation(
      [
        feedback({ state: "retried", path: "static.claims[2]" }),
        feedback({ state: "retried", path: "static.claims[5]" }),
        feedback({ state: "survived", path: "static.claims[5]" }),
        feedback({ state: "resolved", path: "static.claims[2]" }),
      ],
      ROSTER,
    );

    const items = stages[0].rounds[0].items;
    expect(items.map((i) => i.path)).toEqual(["static.claims[2]", "static.claims[5]"]);
    expect(items.map((i) => i.feedback?.map((f) => f.state))).toEqual([
      ["retried", "resolved"],
      ["retried", "survived"],
    ]);
  });

  it("keeps two agents' violations of one code apart", () => {
    const { stages } = buildConversation(
      [feedback({ agent: "lead" }), feedback({ agent: "ahmet" })],
      ROSTER,
    );

    expect(stages[0].rounds[0].items.map((i) => i.speaker)).toEqual(["lead", "ahmet"]);
  });

  it("folds a run that published no path on the pair such a run has", () => {
    const { stages } = buildConversation(
      [
        feedback({ state: "retried" }),
        feedback({ state: "survived" }),
      ],
      ROSTER,
    );

    const items = stages[0].rounds[0].items;
    expect(items).toHaveLength(1);
    expect(items[0].path).toBe("");
    expect(items[0].feedback?.map((f) => f.state)).toEqual(["retried", "survived"]);
  });

  it("reads a line that states no outcome as one the producer was shown", () => {
    /* A run recorded before the outcome was published at all: one line per
     * violation, and that line is the correction turn. */
    const { stages } = buildConversation([feedback({})], ROSTER);

    expect(stages[0].rounds[0].items[0].feedback).toEqual([
      { state: "retried", message: "cite a call", retryIndex: 1 },
    ]);
  });

  it("carries the last retry number and message the violation was published with", () => {
    const { stages } = buildConversation(
      [
        feedback({ state: "retried", retry_index: 1, message: "cite a call" }),
        feedback({ state: "survived", retry_index: 2, message: "still no call cited" }),
      ],
      ROSTER,
    );

    const item = stages[0].rounds[0].items[0];
    expect(item.retryIndex).toBe(2);
    expect(item.text).toBe("still no call cited");
  });
});

describe("streamed turns", () => {
  it("appends deltas into one open bubble", () => {
    const { stages } = buildConversation(
      [
        event("agent_message_delta", { stage: "a", agent: "lead", text_delta: "Reading " }),
        event("agent_message_delta", { stage: "a", agent: "lead", text_delta: "the imports" }),
      ],
      ROSTER,
    );

    const items = stages[0].rounds[0].items;
    expect(items).toHaveLength(1);
    expect(items[0].text).toBe("Reading the imports");
    expect(items[0].streaming).toBe(true);
  });

  it("replaces the open bubble with the message that closes the turn", () => {
    const { stages } = buildConversation(
      [
        event("agent_message_delta", { stage: "a", agent: "lead", text_delta: "Reading " }),
        event("agent_message", { stage: "a", speaker: "lead", round: 0, text: "2 claims from the static layer." }),
      ],
      ROSTER,
    );

    const items = stages[0].rounds[0].items;
    expect(items).toHaveLength(1);
    expect(items[0].streaming).toBeUndefined();
    expect(items[0].text).toBe("2 claims from the static layer.");
  });

  it("keeps two speakers' open turns apart", () => {
    const { stages } = buildConversation(
      [
        event("agent_message_delta", { stage: "a", agent: "lead", text_delta: "lead says" }),
        event("agent_message_delta", { stage: "a", agent: "ahmet", text_delta: "ahmet says" }),
      ],
      ROSTER,
    );

    expect(stages[0].rounds[0].items.map((i) => i.speaker)).toEqual(["lead", "ahmet"]);
  });
});

describe("participants", () => {
  it("names everyone by the label their operator gave them", () => {
    const { participants } = buildConversation(
      [event("agent_message", { stage: "analysis", speaker: "lead", text: "hello" })],
      ROSTER,
    );

    expect(participants.map((p) => p.name)).toEqual(["Lead analyst", "Ahmet", "Judge"]);
    expect(participants.find((p) => p.key === "ahmet")?.via).toEqual(["lead"]);
  });

  it("adds a speaker the roster never mentioned", () => {
    const { participants } = buildConversation(
      [event("agent_message", { speaker: "mehmet", display_name: "Mehmet", text: "hello" })],
      ROSTER,
    );

    expect(participants.map((p) => p.key)).toContain("mehmet");
    expect(participants.find((p) => p.key === "mehmet")?.name).toBe("Mehmet");
  });

  it("leaves a speaker that already reads as a name alone", () => {
    const { participants } = buildConversation(
      [event("agent_message", { speaker: "Sycophancy detector", role: "system", kind: "system", text: "flagged" })],
      null,
    );

    expect(participants[0].name).toBe("Sycophancy detector");
  });

  it("falls back to a readable name when nothing carries a label", () => {
    const { participants } = buildConversation(
      [event("agent_message", { speaker: "static_r2", text: "hello" })],
      null,
    );

    expect(participants[0].name).toBe("Static R2");
  });

  it("says what each participant is doing and how much it has done", () => {
    const { participants } = buildConversation(
      [
        event("agent_progress", { agent: "lead", phase: "analyzing" }),
        event("tool_call_started", { stage: "analysis", agent: "lead", tool: "afl" }),
        event("tool_call_finished", { stage: "analysis", agent: "lead", tool: "afl", ok: true }),
        event("agent_message", { stage: "analysis", speaker: "lead", text: "done" }),
        event("agent_progress", { agent: "ahmet", phase: "analyzing" }),
      ],
      ROSTER,
    );

    const lead = participants.find((p) => p.key === "lead");
    const ahmet = participants.find((p) => p.key === "ahmet");
    expect(lead).toMatchObject({ state: "done", messages: 1 });
    expect(ahmet?.state).toBe("working");
  });
});

describe("filters", () => {
  const conversation = buildConversation(
    [
      event("stage_started", { stage: "analysis", kind: "analysis" }),
      event("agent_message", { stage: "analysis", speaker: "lead", text: "lead speaks" }),
      event("agent_message", { stage: "analysis", speaker: "ahmet", text: "ahmet speaks" }),
      event("tool_call_finished", { stage: "analysis", agent: "lead", tool: "afl", ok: true, evidence_id: "ev_1" }),
      event("validation_feedback", { stage: "analysis", agent: "lead", code: "no_evidence", message: "cite" }),
    ],
    ROSTER,
  );

  it("keeps everything when nothing is chosen", () => {
    const kept = filterConversation(conversation.stages, { agents: new Set(), groups: new Set() });
    expect(itemsOf(kept)).toHaveLength(4);
  });

  it("narrows to one agent", () => {
    const kept = filterConversation(conversation.stages, { agents: new Set(["ahmet"]), groups: new Set() });
    expect(kept[0].rounds[0].items.map((i) => i.text)).toEqual(["ahmet speaks"]);
  });

  it("narrows to one kind of line", () => {
    const kept = filterConversation(conversation.stages, { agents: new Set(), groups: new Set(["tools"] as const) });
    expect(kept[0].rounds[0].items.map((i) => i.tool?.evidenceId)).toEqual(["ev_1"]);
  });

  it("drops a stage a filter emptied", () => {
    const kept = filterConversation(conversation.stages, { agents: new Set(["nobody"]), groups: new Set() });
    expect(kept).toEqual([]);
  });
});

describe("counts", () => {
  it("counts each agent's answered calls", () => {
    const counts = toolCallsFromFeed([
      event("tool_call_started", { agent: "lead", tool: "afl" }),
      event("tool_call_finished", { agent: "lead", tool: "afl", ok: true }),
      event("tool_call_finished", { agent: "lead", tool: "iij", ok: false }),
      event("tool_call_finished", { agent: "ahmet", tool: "afl", ok: true }),
    ]);

    expect(counts).toEqual({ lead: 2, ahmet: 1 });
  });
});
