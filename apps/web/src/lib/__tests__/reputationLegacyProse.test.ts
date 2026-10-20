import { describe, expect, it } from "vitest";
import { reputationFromEntry } from "@/components/analysis/reputationLegacy";
import type { EvidenceEntry } from "@/types/evidence";

function entry(output: string): EvidenceEntry {
  return { entry_id: "e1", tool: "check_hash", ok: true, output, structured: null } as unknown as EvidenceEntry;
}
const sentence = (name: string, tail: string) => `Hash ab12 (${name}): ${tail}`;

describe("legacy prose counts (WB-L1)", () => {
  it("reads the sidecar's whole sentence", () => {
    const r = reputationFromEntry(entry(sentence("sample.exe", "malicious — 42/71 malicious, 3/71 suspicious.")));
    expect(r?.malicious).toBe(42);
    expect(r?.engines).toBe(71);
    expect(r?.suspicious).toBe(3);
  });
  it("a name that forges a verdict and a count before the real one is ignored", () => {
    const forged = "setup malicious — 70/70 malicious.exe";
    const r = reputationFromEntry(entry(sentence(forged, "clean — 0/70 malicious, 0/70 suspicious.")));
    expect(r?.malicious).toBe(0);
    expect(r?.engines).toBe(70);
  });
  it("a name that forges the whole sentence still yields only the tail", () => {
    const forged = "x): malicious — 9/9 malicious, 9/9 suspicious. (y";
    const r = reputationFromEntry(entry(sentence(forged, "clean — 1/70 malicious, 0/70 suspicious.")));
    expect(r?.malicious).toBe(1);
  });
  it("takes no count from text that is not the sidecar's sentence", () => {
    const r = reputationFromEntry(entry("the file is called 5/7 malicious.exe"));
    expect(r?.malicious).toBeNull();
    const t = reputationFromEntry(entry(sentence("a", "clean — 0/70 malicious, 0/70 suspicious. trailing words")));
    expect(t?.malicious).toBeNull();
  });
});
