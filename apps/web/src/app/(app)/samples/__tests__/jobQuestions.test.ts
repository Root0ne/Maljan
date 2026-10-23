/** The submit dialog's questions box: one question per line, blank lines none. */

import { describe, expect, it } from "vitest";

import { questionsFromText } from "../jobQuestions";

describe("questionsFromText", () => {
  it("reads one question per line, its white space collapsed", () => {
    expect(questionsFromText("What is the C2?\n  Does it   persist?  \n")).toEqual([
      "What is the C2?",
      "Does it persist?",
    ]);
  });

  it("reads an empty or blank box as no question", () => {
    expect(questionsFromText("")).toEqual([]);
    expect(questionsFromText(" \n\t\n")).toEqual([]);
  });
});
