import { describe, expect, it } from "vitest";
import { verdictSlices } from "@/app/(app)/dashboard/verdictSlices";

describe("verdict chart slices (WA-L14)", () => {
  it("keeps runs without a verdict as Unknown", () => {
    const slices = verdictSlices({ Malware: 2, malicious: 1, Benign: 1, inconclusive: 3, "": 1 });
    expect(slices).toEqual([
      { bucket: "malicious", name: "Malicious", value: 3 },
      { bucket: "benign", name: "Benign", value: 1 },
      { bucket: "unknown", name: "Unknown", value: 4 },
    ]);
  });
  it("is empty for no data", () => {
    expect(verdictSlices(null)).toEqual([]);
  });
});
