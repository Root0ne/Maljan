import { describe, expect, it } from "vitest";
import {
  boxNumber,
  debatePlaceholder,
  describeDebate,
  patchDebate,
} from "@/app/(app)/settings/configuration/debateOptions";

describe("debate options (WA-L6)", () => {
  it("setting one field invents no other", () => {
    expect(patchDebate(null, "max_rounds", 5)).toEqual({ max_rounds: 5 });
    expect(patchDebate({ max_rounds: 5 }, "consensus_threshold", 0.9)).toEqual({
      max_rounds: 5,
      consensus_threshold: 0.9,
    });
  });
  it("an emptied box is left out, and nothing left means inherit (null)", () => {
    expect(boxNumber("")).toBeNull();
    expect(boxNumber("0")).toBe(0);
    expect(patchDebate({ max_rounds: 5 }, "max_rounds", boxNumber(""))).toBeNull();
    expect(patchDebate({ max_rounds: 5, consensus_threshold: 0.9 }, "max_rounds", null)).toEqual({
      consensus_threshold: 0.9,
    });
  });
  it("a lone default sycophancy check is no options at all", () => {
    expect(patchDebate(null, "sycophancy_check", true)).toBeNull();
    expect(patchDebate(null, "sycophancy_check", false)).toEqual({ sycophancy_check: false });
    expect(patchDebate({ max_rounds: 2, sycophancy_check: false }, "sycophancy_check", true)).toEqual({
      max_rounds: 2,
      sycophancy_check: true,
    });
  });
  it("the placeholder says what the API will use", () => {
    expect(debatePlaceholder(null, "max_rounds")).toBe("global");
    expect(debatePlaceholder({ consensus_threshold: 0.9 }, "max_rounds")).toBe("3 (default)");
    expect(debatePlaceholder({ max_rounds: 2 }, "consensus_threshold")).toBe("0.8 (default)");
  });
  it("describes only what is set", () => {
    expect(describeDebate({ max_rounds: 4 })).toBe("debate 4 round(s)");
    expect(describeDebate(null)).toBe("debate options cleared");
  });
});
