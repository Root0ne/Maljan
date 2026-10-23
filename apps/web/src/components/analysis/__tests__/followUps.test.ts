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
import { canAskFollowUp, followUpRows, modelLine, questionToSend } from "../followUps";
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
    expect(markup).toContain("F1. Which address does it beacon to?");
    expect(markup).toContain("established");
    expect(markup).toContain("It beacons to the address in [ev_0007].");
    expect(markup).toContain("/analysis/j1/evidence?evidence=ev_0007");
    expect(markup).toContain("aaaaaaaaaaaa");
    expect(markup).toContain("recorded on the audit chain");
  });

  it("say a refused word and the platform's check beside the outcome", () => {
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
      "not determinable from this run (the report model answered established; " +
        "the platform&#x27;s check refused it)"
    );
    expect(markup).toContain("Platform check: refused: answered established");
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
