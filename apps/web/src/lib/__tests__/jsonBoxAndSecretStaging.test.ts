import { describe, expect, it } from "vitest";
import {
  canStageSecret,
  readJsonBox,
  unreadBoxNote,
} from "@/app/(app)/settings/configuration/boxReading";

describe("JSON box and secret staging (WA-L1, WA-L2)", () => {
  it("reads valid JSON and reports invalid JSON", () => {
    expect(readJsonBox('{"a":1}')).toEqual({ value: { a: 1 } });
    expect("error" in readJsonBox("{oops")).toBe(true);
  });
  it("names the box that holds Apply", () => {
    expect(unreadBoxNote("Providers", "bad")).toContain("Providers");
  });
  it("an empty secret is not stageable", () => {
    expect(canStageSecret("")).toBe(false);
    expect(canStageSecret("x")).toBe(true);
  });
});
