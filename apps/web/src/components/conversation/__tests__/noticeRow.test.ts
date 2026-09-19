/**
 * The note one violation leaves in the conversation.
 *
 * Rendered rather than inspected, because what is under test is what a reader
 * sees: that the three states are told apart by words and not only by the
 * colour they are drawn in, and that the states a violation passed through on
 * its way here are still on the row that folded them.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import NoticeRow from "@/components/conversation/NoticeRow";
import type { ConversationItem, FeedbackEntry, ValidationState } from "@/lib/conversation";

function correction(feedback: FeedbackEntry[], text: string): ConversationItem {
  const latest = feedback[feedback.length - 1];
  return {
    id: "seq:4",
    kind: "validation_feedback",
    stage: "analysis",
    round: 0,
    speaker: "lead",
    displayName: "Lead analyst",
    text,
    ts: "2026-09-17T10:00:00Z",
    claims: [],
    dissent: [],
    code: "no_evidence",
    path: "static.claims[2]",
    retryIndex: latest?.retryIndex ?? 0,
    feedback,
  };
}

function render(item: ConversationItem): string {
  return renderToStaticMarkup(createElement(NoticeRow, { item }));
}

const WORDS: Record<ValidationState, string> = {
  retried: "sent back for correction",
  resolved: "fixed on the retry",
  survived: "not fixed",
};

describe("a correction", () => {
  it("says in words where the violation ended up", () => {
    for (const state of ["retried", "resolved", "survived"] as ValidationState[]) {
      const markup = render(
        correction([{ state, message: "cite a call", retryIndex: 1 }], "cite a call"),
      );
      expect(markup).toContain(WORDS[state]);
      for (const other of ["retried", "resolved", "survived"] as ValidationState[]) {
        if (other !== state) expect(markup).not.toContain(WORDS[other]);
      }
    }
  });

  it("keeps what the agent was told under how it ended", () => {
    const markup = render(
      correction(
        [
          { state: "retried", message: "cite a call", retryIndex: 1 },
          { state: "survived", message: "still no call cited", retryIndex: 2 },
        ],
        "still no call cited",
      ),
    );

    expect(markup).toContain(WORDS.survived);
    expect(markup).toContain("still no call cited");
    expect(markup).toContain(`retry 1 · ${WORDS.retried} — cite a call`);
  });

  it("leaves the rule key and the locator on the row rather than in the sentence", () => {
    const markup = render(
      correction([{ state: "resolved", message: "cite a call", retryIndex: 1 }], "cite a call"),
    );

    expect(markup).toContain('title="no_evidence · static.claims[2]"');
  });

  it("draws a line that carries no states at all", () => {
    const item = correction([], "cite a call");
    const markup = render({ ...item, feedback: undefined, path: "" });

    expect(markup).toContain("cite a call");
    expect(markup).toContain(WORDS.retried);
  });
});

describe("a notice the room made", () => {
  it("carries no correction state", () => {
    const markup = render({
      id: "seq:9",
      kind: "system",
      stage: "analysis",
      round: 0,
      speaker: "",
      displayName: "",
      text: "Lead analyst stopped on its round cap.",
      ts: "2026-09-17T10:00:00Z",
      claims: [],
      dissent: [],
    });

    expect(markup).toContain("stopped on its round cap");
    for (const word of Object.values(WORDS)) expect(markup).not.toContain(word);
  });
});
