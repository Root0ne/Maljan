import { describe, expect, it } from "vitest";
import { manifestOutcome } from "@/app/(app)/settings/configuration/manifestOutcome";
import type { ProbeResult } from "@/types/settings";

const base = { latency_ms: 1, models: null, details: null };

describe("tool listing outcome (WA-L4)", () => {
  it("a failed probe is an error, not an empty list", () => {
    const out = manifestOutcome({ ...base, ok: false, detail: "ConnectError: refused", tools: null } as ProbeResult);
    expect("error" in out).toBe(true);
  });
  it("an answer without a manifest is an error", () => {
    expect("error" in manifestOutcome({ ...base, ok: true, detail: "ok", tools: null } as ProbeResult)).toBe(true);
  });
  it("an answered empty manifest is an empty list", () => {
    expect(manifestOutcome({ ...base, ok: true, detail: "ok", tools: [] } as ProbeResult)).toEqual({ tools: [] });
  });
});
