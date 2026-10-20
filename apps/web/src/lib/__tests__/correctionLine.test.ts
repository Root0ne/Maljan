import { describe, expect, it } from "vitest";
import { correctionLine } from "@/app/(app)/analysis/[id]/correctionLine";

const label = (n: number, noun: string) => `${n} ${noun}${n === 1 ? "" : "s"}`;

describe("run record correction line (WA-L8)", () => {
  it("says the report does not record it when the block is missing", () => {
    expect(correctionLine(null, label)).toMatch(/does not record/);
    expect(correctionLine({}, label)).toMatch(/does not record/);
  });
  it("says zero only when zero was recorded", () => {
    expect(correctionLine({ retries: 0 }, label)).toBe("No producer needed a correction turn.");
    expect(correctionLine({ retries: 2 }, label)).toContain("2 correction turns");
  });
});
