/**
 * Follow-up questions on a finished run: when one can be asked, what is sent,
 * and how the answers are drawn. Rendered rather than inspected, because what
 * is under test is what a reader sees: every text the model or the analyst
 * wrote arrives as plain text, never as markup.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { FollowUpList } from "../FollowUpQuestions";
import {
  canAskFollowUp,
  composerKey,
  followUpRows,
  modelLine,
  questionToSend,
  suggestedQuestions,
} from "../followUps";
import type { FollowUp } from "@/types/malware-report";

const HOSTILE = '<img src=x onerror="alert(1)"><script>alert(2)</script>';

function row(over: Partial<FollowUp> = {}): FollowUp {
  return {
    id: "f1",
    job_id: "j1",
    report_id: "r1",
    question: "Which address does it beacon to?",
    outcome: "established",
    answer: {
      question: "Which address does it beacon to?",
      outcome: "established",
      answer: "It beacons to the address in [ev_0007].",
      evidence_ids: ["ev_0007"],
      looked_at: [],
      open_questions: [],
      checks: [],
    },
    model: "openai gpt-test",
    model_source: "the reporter's model this run's settings snapshot recorded",
    report_sha256: "a".repeat(64),
    record: { digest: "d" },
    notes: [],
    answered_at: "2026-10-23T10:00:00Z",
    ...over,
  };
}

function render(rows: FollowUp[]): string {
  return renderToStaticMarkup(createElement(FollowUpList, { rows, jobId: "j1" }));
}

describe("a follow-up question", () => {
  it("can be asked of a finished job only", () => {
    for (const status of ["completed", "failed", "cancelled"]) {
      expect(canAskFollowUp(status)).toBe(true);
    }
    for (const status of ["pending", "running", "", null, undefined]) {
      expect(canAskFollowUp(status)).toBe(false);
    }
  });

  it("is sent on one line, and a blank one is not sent", () => {
    expect(questionToSend("  Does it\n persist?  ")).toBe("Does it persist?");
    expect(questionToSend(" \n\t ")).toBe("");
  });

  it("is listed in order, a row without a question left out", () => {
    const rows = followUpRows([row(), row({ id: "f2", question: "  " })]);
    expect(rows.map((r) => r.id)).toEqual(["f1"]);
    expect(followUpRows(null)).toEqual([]);
  });

  it("is sent with Enter, and Shift+Enter or a composing input method starts no send", () => {
    expect(composerKey({ key: "Enter", shiftKey: false })).toBe("send");
    expect(composerKey({ key: "Enter", shiftKey: true })).toBe("newline");
    expect(composerKey({ key: "Enter", shiftKey: false, ctrlKey: true })).toBe("newline");
    expect(composerKey({ key: "Enter", shiftKey: false, isComposing: true })).toBeNull();
    expect(composerKey({ key: "a", shiftKey: false })).toBeNull();
  });

  it("is suggested from the open questions the analysis left, written as questions and not yet asked", () => {
    const mr = {
      question_answers: [
        {
          ...row().answer,
          open_questions: ["Which mutex does it create?", "the launcher is not identified", "Does it persist?"],
        },
      ],
    };
    const asked = row({
      question: "Does it persist?",
      answer: { ...row().answer, open_questions: ["Who launched rundll32?", "Which mutex does it create?"] },
    });
    // Newest follow-up first, then the submission's; once each; a statement is not offered.
    expect(suggestedQuestions(mr, [asked])).toEqual(["Who launched rundll32?", "Which mutex does it create?"]);
    expect(suggestedQuestions(null, null)).toEqual([]);
  });

  it("says where its model came from", () => {
    expect(modelLine(row())).toBe(
      "openai gpt-test (the reporter's model this run's settings snapshot recorded)"
    );
    expect(modelLine(row({ model: "", model_source: "" }))).toBe("no model");
  });
});

describe("the follow-ups drawn", () => {
  it("say so when none was asked", () => {
    expect(render([])).toContain("No follow-up question has been asked.");
  });

  it("draw the outcome, the answer, the evidence and the report it was answered from", () => {
    const markup = render([row()]);
    expect(markup).toContain("You asked: </span>Which address does it beacon to?");
    expect(markup).toContain("established");
    // The answer's bracketed citation is a mark, not printed ids.
    expect(markup).toContain("It beacons to the address in");
    expect(markup).not.toContain("[ev_0007]");
    // The record the answer cites in its text is marked there once, not listed again.
    expect(markup.match(/data-citation/g)).toHaveLength(1);
    expect(markup).toContain('title="ev_0007"');
    expect(markup).not.toContain("evidence=ev_0007");
    // A record the answer rests on but does not cite in its text is still listed.
    expect(render([row({ answer: { ...row().answer, evidence_ids: ["ev_0007", "ev_0009"] } })])).toContain(
      "/analysis/j1/evidence/records?evidence=ev_0009",
    );
    expect(markup).toContain("aaaaaaaaaaaa");
    expect(markup).toContain("recorded on the audit chain");
  });

  it("say a refused word and the automatic check beside the outcome", () => {
    const markup = render([
      row({
        outcome: "not_determinable",
        answer: {
          ...row().answer,
          outcome: "not_determinable",
          answered: "established",
          checks: ["refused: answered established, but no entry it cites answered"],
        },
        record: null,
        notes: ["this follow-up is not on the audit chain: no key"],
      }),
    ]);
    expect(markup).toContain(
      "not determinable from this run (the AI answer said established; " +
        "an automatic check did not accept it)"
    );
    expect(markup).toContain("Check: refused: answered established");
    expect(markup).toContain("Note: this follow-up is not on the audit chain: no key");
    expect(markup).not.toContain("recorded on the audit chain");
  });

  it("draw every text the model or the analyst wrote as text, never as markup", () => {
    const markup = render([
      row({
        question: HOSTILE,
        answer: {
          ...row().answer,
          question: HOSTILE,
          answer: HOSTILE,
          open_questions: [HOSTILE],
          checks: [HOSTILE],
        },
        notes: [HOSTILE],
        model: HOSTILE,
      }),
    ]);
    expect(markup).not.toContain("<img");
    expect(markup).not.toContain("<script");
    expect(markup).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
    expect(markup).toContain("&lt;script&gt;alert(2)&lt;/script&gt;");
  });
});
