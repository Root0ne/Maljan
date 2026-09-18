/**
 * Reading a failure's error id off what the worker published.
 *
 * The shapes are the two `failure_reason` writes — the sentence the worker
 * composed for an operator, and the bare class of everything else — plus the
 * two a console has to survive: a failure with no id at all, which is every
 * run recorded before the id existed, and one whose text carries two.
 */

import { describe, expect, it } from "vitest";

import { jobFailure, runFailure } from "@/lib/runFailure";

const ID = "5f3a9c1d4e2b48f7a0c6d8e1b3f5a7c9";
const OTHER = "0011223344556677889900aabbccddee";

describe("a failure's error id", () => {
  it("comes off a sentence the worker wrote", () => {
    expect(runFailure(`The sandbox provider cannot take this sample. (error id ${ID})`)).toEqual({
      sentence: "The sandbox provider cannot take this sample.",
      errorId: ID,
    });
  });

  it("comes off a bare exception class", () => {
    expect(runFailure(`ValueError (error id ${ID})`)).toEqual({
      sentence: "ValueError",
      errorId: ID,
    });
  });

  it("is absent from a failure that carries none, which is left as it was", () => {
    expect(runFailure("ValueError: the sample could not be read")).toEqual({
      sentence: "ValueError: the sample could not be read",
      errorId: null,
    });
  });

  it("is the first of two, which is the failure the run ended on", () => {
    const failure = runFailure(
      `RuntimeError (error id ${ID}) while recording (error id ${OTHER})`,
    );

    expect(failure.errorId).toBe(ID);
    expect(failure.sentence).toBe(`RuntimeError while recording (error id ${OTHER})`);
  });

  it("is the field, where the API answers with one", () => {
    /* The `error` event states the id on its own key, and its message is the
     * one sentence the worker publishes to every reader. */
    const failure = runFailure("Analysis failed. See server logs for details.", ID);

    expect(failure).toEqual({
      sentence: "Analysis failed. See server logs for details.",
      errorId: ID,
    });
  });

  it("survives a run that recorded no failure text", () => {
    expect(runFailure(null)).toEqual({ sentence: "", errorId: null });
    expect(runFailure(undefined)).toEqual({ sentence: "", errorId: null });
  });
});

describe("what a job row says about its ending", () => {
  it("is the failure, for a run that failed", () => {
    expect(jobFailure("failed", `ValueError (error id ${ID})`)).toEqual({
      sentence: "ValueError",
      errorId: ID,
    });
  });

  it("is nothing for a run an operator cancelled", () => {
    /* The cancel is the operator's decision, recorded with no message and
     * outranking whatever the run was raising as it went down. Drawing a
     * failure over it would report the stop as a fault. */
    expect(jobFailure("cancelled", null)).toBeNull();
    expect(jobFailure("cancelled", `ValueError (error id ${ID})`)).toBeNull();
  });

  it("is nothing for a run that is still going or has finished", () => {
    for (const status of ["pending", "running", "completed"]) {
      expect(jobFailure(status, null)).toBeNull();
    }
  });

  it("is nothing for a failed row that recorded no message at all", () => {
    expect(jobFailure("failed", null)).toBeNull();
    expect(jobFailure("failed", "   ")).toBeNull();
  });
});
