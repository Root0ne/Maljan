// @vitest-environment jsdom
/**
 * A new line redraws the new line, not the conversation.
 *
 * The bubbles are memoised, and that only holds while every prop they get
 * holds still from one event to the next — the item, the tone, the quote of
 * the question it answers. This mounts the panel on a feed, appends one
 * message, and counts which messages were drawn again: the probe is the
 * Markdown renderer, which every bubble calls once per draw.
 */

import { act, createElement } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const draws: string[] = [];
vi.mock("@/components/analysis/SafeMarkdown", () => ({
  default: ({ markdown }: { markdown: string }) => {
    draws.push(markdown);
    return createElement("p", null, markdown);
  },
}));

import ConversationPanel from "@/components/conversation/ConversationPanel";
import { resetConversationCache } from "@/lib/conversation";
import type { RunEvent } from "@/lib/runStore";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let seq = 0;
function event(type: string, data: Record<string, unknown>): RunEvent {
  seq += 1;
  return { type, data: { seq, ...data }, ts: "2026-10-27T03:00:00Z", seq, order: seq, sortKey: seq };
}

function said(speaker: string, text: string, extra: Record<string, unknown> = {}): RunEvent {
  return event("agent_message", { stage: "debate", speaker, display_name: speaker.toUpperCase(), round: 1, kind: "says", text, ...extra });
}

let mount: HTMLDivElement;
let root: Root;

beforeEach(() => {
  resetConversationCache();
  draws.length = 0;
  mount = document.createElement("div");
  document.body.append(mount);
  root = createRoot(mount);
});

afterEach(() => {
  act(() => root.unmount());
  mount.remove();
});

function panel(events: RunEvent[]) {
  return createElement(ConversationPanel, {
    jobId: "job",
    events,
    lastSeq: events.length,
    roster: null,
    connection: "open",
    feedError: null,
    live: true,
    jobStatus: "running",
  });
}

describe("appending one event", () => {
  it("draws only the new message again", () => {
    const feed = [
      event("stage_started", { stage: "debate", kind: "debate" }),
      event("agent_message", {
        stage: "debate",
        speaker: "pipeline",
        role: "negotiator",
        kind: "system",
        round: 1,
        text: "Mediator: two lines stay open.",
      }),
      said("static", "Line one is closed by ev_0004."),
      said("dynamic", "Line two stands."),
      event("tool_call_finished", { stage: "debate", agent: "dynamic", tool: "t", ok: true, duration_ms: 5, evidence_id: "ev_0009" }),
    ];
    act(() => root.render(panel(feed)));
    expect(draws).toContain("Line one is closed by ev_0004.");

    draws.length = 0;
    const next = [...feed, said("network", "Both lines are settled.")];
    act(() => root.render(panel(next)));
    expect(draws).toEqual(["Both lines are settled."]);
  });
});
