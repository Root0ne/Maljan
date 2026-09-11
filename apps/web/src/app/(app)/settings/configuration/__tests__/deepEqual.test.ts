import { describe, expect, it } from "vitest";
import { deepEqual } from "../deepEqual";

describe("deepEqual", () => {
  it("treats objects with the same entries in a different key order as equal", () => {
    expect(deepEqual({ a: 1, b: 2 }, { b: 2, a: 1 })).toBe(true);
  });

  it("is order-sensitive for arrays", () => {
    expect(deepEqual([1, 2], [2, 1])).toBe(false);
    expect(deepEqual([1, 2], [1, 2])).toBe(true);
  });

  it("distinguishes null from undefined", () => {
    expect(deepEqual(null, undefined)).toBe(false);
    expect(deepEqual(null, null)).toBe(true);
    expect(deepEqual(undefined, undefined)).toBe(true);
  });

  it("treats null/undefined leaves as unequal to any other value", () => {
    expect(deepEqual(null, 0)).toBe(false);
    expect(deepEqual(undefined, "")).toBe(false);
  });

  it("compares nested structures structurally", () => {
    expect(deepEqual({ a: [1, { x: 1, y: 2 }] }, { a: [1, { y: 2, x: 1 }] })).toBe(true);
    expect(deepEqual({ a: [1, { x: 1, y: 2 }] }, { a: [1, { y: 2, x: 3 }] })).toBe(false);
  });

  it("returns false when object key counts differ", () => {
    expect(deepEqual({ a: 1 }, { a: 1, b: 2 })).toBe(false);
  });

  it("uses === for primitives and identity", () => {
    expect(deepEqual(1, 1)).toBe(true);
    expect(deepEqual("x", "x")).toBe(true);
    expect(deepEqual(1, "1")).toBe(false);
  });
});
