/** The questions a job was asked, read and worded as the exported report words them. */

import { describe, expect, it } from "vitest";

import type { MalwareReport, QuestionAnswer } from "@/types/malware-report";
import { OUTCOME_WORDS, outcomeLine, questionAnswers } from "../reportProse";

function answer(over: Partial<QuestionAnswer>): QuestionAnswer {
  return {
    question: "What is the C2 address?",
    outcome: "established",
    answer: "",
    evidence_ids: [],
    looked_at: [],
    open_questions: [],
    checks: [],
    ...over,
  };
}

describe("the questions asked of a run", () => {
  it("are none on a report of a job asked nothing", () => {
    expect(questionAnswers({} as MalwareReport)).toEqual([]);
    expect(questionAnswers(null)).toEqual([]);
  });

  it("are read in order, a blank question left out", () => {
    const mr = {
      question_answers: [answer({}), answer({ question: "  " })],
    } as MalwareReport;
    expect(questionAnswers(mr).map((a) => a.question)).toEqual(["What is the C2 address?"]);
  });

  it("word each outcome as the exported report does", () => {
    expect(Object.values(OUTCOME_WORDS)).toEqual([
      "established",
      "partial",
      "limited negative",
      "not determinable from this run",
      "out of scope",
    ]);
    expect(outcomeLine(answer({ outcome: "limited_negative" }))).toBe("limited negative");
  });

  it("say a refused word beside the outcome the report stands by", () => {
    expect(outcomeLine(answer({ outcome: "not_determinable", answered: "established" }))).toBe(
      "not determinable from this run (the report model answered established; " +
        "the platform's check refused it)"
    );
  });
});
