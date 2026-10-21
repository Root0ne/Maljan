import { describe, expect, it } from "vitest";

import { ceilingValue, storedCeilings } from "@/app/(app)/settings/configuration/modelList";

describe("ceilingValue", () => {
  it("reads a blank field as no ceiling", () => {
    expect(ceilingValue("")).toBeNull();
    expect(ceilingValue("   ")).toBeNull();
  });

  it("reads a positive number as the ceiling", () => {
    expect(ceilingValue("2.5")).toBe(2.5);
    expect(ceilingValue("200000", true)).toBe(200000);
  });

  it("stages nothing for text that is not a positive number", () => {
    expect(ceilingValue("0")).toBeUndefined();
    expect(ceilingValue("0.")).toBeUndefined();
    expect(ceilingValue("-1")).toBeUndefined();
    expect(ceilingValue("abc")).toBeUndefined();
  });

  it("takes only a whole number for the token ceiling", () => {
    expect(ceilingValue("1.5", true)).toBeUndefined();
    expect(ceilingValue("1.5")).toBe(1.5);
  });
});

describe("storedCeilings", () => {
  it("stores nothing for an entry with no ceiling, so it is staged as before", () => {
    expect(storedCeilings({})).toEqual({});
    expect(storedCeilings({ max_spend_usd: null, max_unpriced_tokens: null })).toEqual({});
  });

  it("stores each ceiling that is set", () => {
    expect(storedCeilings({ max_spend_usd: 1.25 })).toEqual({ max_spend_usd: 1.25 });
    expect(storedCeilings({ max_unpriced_tokens: 50000, max_spend_usd: null })).toEqual({
      max_unpriced_tokens: 50000,
    });
  });
});
