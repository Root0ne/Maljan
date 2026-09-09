import { describe, expect, it } from "vitest";
import { isProbeStale, probeFingerprint } from "../probeStale";

describe("probe staleness", () => {
  it("is not stale while the staged values are unchanged", () => {
    const before = probeFingerprint({ "core.llm.provider": "openai", "core.llm.openai.api_key": "sk-1" });
    const after = probeFingerprint({ "core.llm.provider": "openai", "core.llm.openai.api_key": "sk-1" });
    expect(isProbeStale(before, after)).toBe(false);
  });

  it("ignores the order the keys were staged in", () => {
    const before = probeFingerprint({ a: 1, b: 2 });
    const after = probeFingerprint({ b: 2, a: 1 });
    expect(isProbeStale(before, after)).toBe(false);
  });

  it("is stale when a value changes, even though the same keys are staged", () => {
    const before = probeFingerprint({ "core.llm.provider": "openai", "core.llm.openai.api_key": "sk-1" });
    const after = probeFingerprint({ "core.llm.provider": "openai", "core.llm.openai.api_key": "sk-2" });
    expect(isProbeStale(before, after)).toBe(true);
  });

  it("is stale when a key is added or removed", () => {
    const before = probeFingerprint({ "core.llm.provider": "openai" });
    const added = probeFingerprint({ "core.llm.provider": "openai", "core.llm.openai.base_url": "http://x" });
    expect(isProbeStale(before, added)).toBe(true);
    expect(isProbeStale(added, before)).toBe(true);
  });

  it("treats an empty staged set as its own fingerprint", () => {
    expect(isProbeStale(probeFingerprint({}), probeFingerprint({}))).toBe(false);
    expect(isProbeStale(probeFingerprint({}), probeFingerprint({ a: null }))).toBe(true);
  });
});
