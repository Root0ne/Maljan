import { describe, expect, it } from "vitest";

import { rosterNames } from "@/lib/rosterNames";
import type { JobRoster } from "@/types/events";

/** The mandate's own team: three analysts an operator named, of which the
 *  second got the slug `ahmet_1` because the first had taken the name. */
const ROSTER: JobRoster = {
  agents: [
    { key: "ahmet_1", label: "Ahmet", role: "static", stages: ["analysis"] },
    { key: "mehmet", label: "Mehmet", role: "dynamic", stages: ["analysis"] },
    { key: "cemal_2", label: "", role: "network", stages: ["analysis"] },
  ],
  stages: [
    { key: "analysis", label: "Analysis", kind: "analysis", agents: ["ahmet_1", "mehmet"] },
    { key: "verdict", label: "", kind: "verdict", agents: ["judge"] },
  ],
};

describe("what a run calls its agents", () => {
  it("uses the operator's label, never the key it is published under", () => {
    const names = rosterNames(ROSTER);
    expect(names.agent("ahmet_1")).toBe("Ahmet");
    expect(names.agent("mehmet")).toBe("Mehmet");
  });

  it("falls back to the key when the roster names nobody", () => {
    expect(rosterNames(null).agent("ahmet_1")).toBe("ahmet_1");
    expect(rosterNames(undefined).agent("static")).toBe("static");
  });

  it("falls back to the key when the roster has an entry with no label", () => {
    expect(rosterNames(ROSTER).agent("cemal_2")).toBe("cemal_2");
  });

  it("falls back to the key for an agent the roster never listed", () => {
    expect(rosterNames(ROSTER).agent("yara_layer")).toBe("yara_layer");
  });

  it("says whether the roster names an agent at all", () => {
    const names = rosterNames(ROSTER);
    expect(names.hasAgent("ahmet_1")).toBe(true);
    expect(names.hasAgent("cemal_2")).toBe(false);
    expect(names.hasAgent("nobody")).toBe(false);
  });
});

describe("what a run calls its stages", () => {
  it("uses the stage label and falls back to the stage key", () => {
    const names = rosterNames(ROSTER);
    expect(names.stage("analysis")).toBe("Analysis");
    expect(names.stage("verdict")).toBe("verdict");
    expect(names.stage("debate")).toBe("debate");
  });
});

describe("the caller's own fallback", () => {
  it("is used wherever the roster does not answer", () => {
    // The conversation reads a key made readable; a table of published rows
    // reads the key. One reading of the roster, two policies for what is
    // missing from it.
    const names = rosterNames(ROSTER, (key) => key.toUpperCase());
    expect(names.agent("ahmet_1")).toBe("Ahmet");
    expect(names.agent("cemal_2")).toBe("CEMAL_2");
    expect(names.stage("debate")).toBe("DEBATE");
  });
});
