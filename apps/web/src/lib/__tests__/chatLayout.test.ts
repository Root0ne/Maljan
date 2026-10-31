import { describe, expect, it } from "vitest";

import {
  chatBlocks,
  replyTargets,
  stripDuration,
  stripLabel,
  stripSummary,
  type SpeakerGroup,
} from "@/lib/chatLayout";
import {
  filterConversation,
  isFailure,
  itemGroup,
  moderatorOf,
  type ConversationItem,
  type ConversationStage,
} from "@/lib/conversation";

/**
 * The conversation laid out as a group chat.
 *
 * What a reader would notice if these broke: an agent's calls scattered as a
 * row each between its messages, a strip that pulls a call past something
 * another agent said, an answer that quotes the wrong question, and the
 * mediator drawn as a note when it is talking to the team.
 */

let n = 0;
function line(partial: Partial<ConversationItem>): ConversationItem {
  n += 1;
  return {
    id: `seq:${n}`,
    kind: "says",
    stage: "s",
    round: 0,
    speaker: "a",
    displayName: "A",
    text: `line ${n}`,
    ts: "",
    claims: [],
    dissent: [],
    ...partial,
  };
}

function call(speaker: string, ok: boolean | null = true, durationMs = 1000): ConversationItem {
  return line({
    kind: "tool_call",
    speaker,
    displayName: speaker.toUpperCase(),
    tool: { name: "t", server: null, evidenceId: "", ok, durationMs, summary: "" },
  });
}

function stage(items: ConversationItem[]): ConversationStage {
  return {
    id: "stage:s",
    key: "s",
    label: "S",
    kind: "",
    state: "done",
    reason: "",
    durationMs: 0,
    rounds: [{ round: 0, items }],
  };
}

describe("chat blocks", () => {
  it("folds a speaker's calls into one strip under its group", () => {
    const said = line({ speaker: "a" });
    const blocks = chatBlocks([said, call("a"), call("a"), call("a")]);
    expect(blocks).toHaveLength(1);
    const group = blocks[0] as SpeakerGroup;
    expect(group.entries.map((e) => e.type)).toEqual(["message", "tools"]);
    expect(group.entries[1].type === "tools" && group.entries[1].calls).toHaveLength(3);
  });

  it("keeps a strip open across another agent's calls, never across a message", () => {
    const a1 = call("a");
    const b1 = call("b");
    const a2 = call("a");
    const bSays = line({ speaker: "b", displayName: "B" });
    const a3 = call("a");
    const blocks = chatBlocks([a1, b1, a2, bSays, a3]) as SpeakerGroup[];
    expect(blocks.map((b) => b.speaker)).toEqual(["a", "b", "a"]);
    const firstStrip = blocks[0].entries[0];
    expect(firstStrip.type === "tools" && firstStrip.calls).toEqual([a1, a2]);
    // B's call and B's message share B's group.
    expect(blocks[1].entries.map((e) => e.type)).toEqual(["tools", "message"]);
    // After B spoke, A's next call opens a new strip.
    const lastStrip = blocks[2].entries[0];
    expect(lastStrip.type === "tools" && lastStrip.calls).toEqual([a3]);
  });

  it("draws room notes apart and starts a new group on a change of addressee", () => {
    const note = line({ kind: "validation_feedback", speaker: "a" });
    const plain = line({ speaker: "a" });
    const asked = line({ speaker: "a", kind: "delegation_ask", addressedTo: "b" });
    const blocks = chatBlocks([plain, note, line({ speaker: "a" }), asked]);
    expect(blocks.map((b) => b.type)).toEqual(["speaker", "room", "speaker", "speaker"]);
  });

  it("draws the mediator as a speaker of its own", () => {
    const mediator = line({ kind: "system", speaker: "", role: "negotiator", text: "Mediator: Two lines stay open." });
    const blocks = chatBlocks([mediator]);
    expect(blocks[0]).toMatchObject({ type: "speaker", speaker: "moderator:Mediator", moderator: true });
  });
});

describe("moderator lines", () => {
  it("reads the name the moderator introduced itself with", () => {
    const item = line({ kind: "system", speaker: "", role: "negotiator", text: "Mediator: L1 is closed." });
    expect(moderatorOf(item)).toEqual({ name: "Mediator", text: "L1 is closed." });
    expect(itemGroup(item)).toBe("says");
  });

  it("leaves a plain room line a note", () => {
    const item = line({ kind: "system", speaker: "", role: "system", text: "For the line \"x\": ev_1 lists it." });
    expect(moderatorOf(item)).toBeNull();
    expect(itemGroup(item)).toBe("notices");
  });

  it("names a moderator that did not introduce itself by the speaker", () => {
    const item = line({ kind: "system", speaker: "Mediator", displayName: "Mediator", role: "negotiator", text: "uncorroborated." });
    expect(moderatorOf(item)).toEqual({ name: "Mediator", text: "uncorroborated." });
  });
});

describe("replies", () => {
  it("links a directed question to the addressee's next line", () => {
    const question = line({ kind: "judge_question", speaker: "judge", addressedTo: "a" });
    const other = line({ speaker: "b" });
    const answer = line({ speaker: "a" });
    const later = line({ speaker: "a" });
    const replies = replyTargets([stage([question, call("a"), other, answer, later])]);
    expect(replies.get(answer.id)).toBe(question);
    expect(replies.has(other.id)).toBe(false);
    expect(replies.has(later.id)).toBe(false);
  });

  it("links each participant's next line to a moderator speaking to the room", () => {
    const first = line({ kind: "system", speaker: "", role: "negotiator", text: "Mediator: round one." });
    const a = line({ speaker: "a" });
    const b = line({ speaker: "b" });
    const aAgain = line({ speaker: "a" });
    const second = line({ kind: "system", speaker: "", role: "negotiator", text: "Mediator: round two." });
    const aThird = line({ speaker: "a" });
    const replies = replyTargets([stage([first, a, b, aAgain, second, aThird])]);
    expect(replies.get(a.id)).toBe(first);
    expect(replies.get(b.id)).toBe(first);
    expect(replies.has(aAgain.id)).toBe(false);
    expect(replies.get(aThird.id)).toBe(second);
  });

  it("keeps two questions open to one agent apart, by who asked", () => {
    const fromA = line({ speaker: "a", kind: "delegation_ask", addressedTo: "s" });
    const fromB = line({ speaker: "b", kind: "delegation_ask", addressedTo: "s" });
    const toA = line({ speaker: "s", kind: "delegation_answer", addressedTo: "a" });
    const next = line({ speaker: "s" });
    const replies = replyTargets([stage([fromA, fromB, toA, next])]);
    expect(replies.get(toA.id)).toBe(fromA);
    // The answer that names nobody takes the question still open.
    expect(replies.get(next.id)).toBe(fromB);
  });

  it("answers the oldest open question when the answer names no asker", () => {
    const first = line({ speaker: "a", kind: "delegation_ask", addressedTo: "s" });
    const second = line({ speaker: "b", kind: "delegation_ask", addressedTo: "s" });
    const answer = line({ speaker: "s" });
    expect(replyTargets([stage([first, second, answer])]).get(answer.id)).toBe(first);
  });

  it("never reads a moderator's error line as a question", () => {
    const failed = line({
      kind: "system",
      speaker: "",
      role: "negotiator",
      text: "Mediator: [ERROR] the negotiation turn failed.",
    });
    const a = line({ speaker: "a" });
    expect(replyTargets([stage([failed, a])]).has(a.id)).toBe(false);
  });

  it("lets only the team answer a moderator speaking to the room", () => {
    const room = line({ kind: "system", speaker: "", role: "negotiator", text: "Mediator: two lines stay open." });
    const again = line({ kind: "system", speaker: "", role: "negotiator", text: "Mediator: one line stays open." });
    const verdict = line({ speaker: "judge", kind: "verdict", text: "Malicious." });
    const judgeSays = line({ speaker: "judge", text: "Noted." });
    const a = line({ speaker: "a" });
    const replies = replyTargets([stage([room, again, verdict, judgeSays, a])]);
    expect(replies.has(again.id)).toBe(false);
    expect(replies.has(verdict.id)).toBe(false);
    expect(replies.has(judgeSays.id)).toBe(false);
    expect(replies.get(a.id)).toBe(again);
  });

  it("links a delegated answer to its ask", () => {
    const ask = line({ speaker: "lead", kind: "delegation_ask", addressedTo: "ahmet" });
    const answer = line({ speaker: "ahmet", kind: "delegation_answer", addressedTo: "lead" });
    expect(replyTargets([stage([ask, answer])]).get(answer.id)).toBe(ask);
  });
});

describe("strips", () => {
  it("counts calls, time, failures and calls still running", () => {
    const summary = stripSummary([call("a", true, 1500), call("a", false, 500), call("a", null, 0)]);
    expect(summary).toEqual({ calls: 3, failed: 1, running: 1, durationMs: 2000 });
    expect(stripLabel(summary)).toBe("3 tools · 2 s · 1 failed · 1 running");
    expect(stripLabel(stripSummary([call("a", true, 0)]))).toBe("1 tool");
  });

  it("says a duration in the units it is read in", () => {
    expect(stripDuration(0)).toBe("");
    expect(stripDuration(812)).toBe("812 ms");
    expect(stripDuration(34_200)).toBe("34 s");
    expect(stripDuration(125_000)).toBe("2 min 5 s");
    expect(stripDuration(120_000)).toBe("2 min");
  });
});

describe("the failures filter", () => {
  it("keeps every line that records a failure, whatever its group", () => {
    const failedCall = call("a", false);
    const failedTurn = line({ status: "failed" });
    const survived = line({
      kind: "validation_feedback",
      feedback: [{ state: "survived", message: "", retryIndex: 1 }],
    });
    const fine = line({});
    const kept = filterConversation([stage([failedCall, call("a"), failedTurn, survived, fine])], {
      agents: new Set(),
      groups: new Set(["failures"]),
    });
    expect(kept[0].rounds[0].items).toEqual([failedCall, failedTurn, survived]);
    expect(isFailure(fine)).toBe(false);
  });
});
