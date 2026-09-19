import { describe, expect, it } from "vitest";

import { bundleLossSentence } from "@/lib/report-utils";

/**
 * The counts of the eight bundle shapes the reconciliation was measured on.
 * `integrity_objects_removed` counts both integrity passes, and the second one
 * removes nothing but relationships the indicator cap orphaned — so a sentence
 * built from that total called six orphaned relationships "repaired away as
 * malformed or duplicated" on the very shape the counters exist for.
 */
const SHAPES = {
  overTheCap: {
    integrity_objects_removed: 6,
    indicator_cap_removed: 6,
    integrity_refs_trimmed: 18,
    integrity_dropped: { cap_orphan: 6 },
  },
  overTheCapWithAReport: {
    integrity_objects_removed: 6,
    indicator_cap_removed: 6,
    integrity_refs_trimmed: 30,
    integrity_dropped: { cap_orphan: 6 },
  },
  underTheCap: {
    integrity_objects_removed: 0,
    indicator_cap_removed: 0,
    integrity_refs_trimmed: 0,
    integrity_dropped: {},
  },
  benign: {
    integrity_objects_removed: 0,
    indicator_cap_removed: 6,
    integrity_refs_trimmed: 12,
    integrity_dropped: {},
  },
  malformed: {
    integrity_objects_removed: 1,
    indicator_cap_removed: 0,
    integrity_refs_trimmed: 2,
    integrity_dropped: { empty_pattern: 1 },
  },
  duplicates: {
    integrity_objects_removed: 7,
    indicator_cap_removed: 0,
    integrity_refs_trimmed: 0,
    integrity_dropped: { duplicate_indicator: 7 },
  },
  dangling: {
    integrity_objects_removed: 1,
    indicator_cap_removed: 0,
    integrity_refs_trimmed: 0,
    integrity_dropped: { duplicate_attack_pattern: 1 },
  },
  everythingAtOnce: {
    integrity_objects_removed: 10,
    indicator_cap_removed: 6,
    integrity_refs_trimmed: 27,
    integrity_dropped: {
      empty_pattern: 2,
      duplicate_indicator: 1,
      dangling_relationship: 1,
      cap_orphan: 6,
    },
  },
};

describe("bundleLossSentence", () => {
  it("says nothing when the bundle kept everything", () => {
    expect(bundleLossSentence(null)).toBeNull();
    expect(bundleLossSentence(SHAPES.underTheCap)).toBeNull();
  });

  it("says nothing for a summary stored before the counters existed", () => {
    expect(bundleLossSentence({})).toBeNull();
  });

  it("does not call a capped relationship a repair", () => {
    const text = bundleLossSentence(SHAPES.overTheCap);
    expect(text).not.toContain("repaired away");
    expect(text).toContain("6 indicators over the export's total cap");
    expect(text).toContain("6 relationships left pointing at a capped indicator");
    expect(text).toContain("18 references trimmed from a report or a note");
  });

  it("names each reason with its own count", () => {
    const text = bundleLossSentence(SHAPES.everythingAtOnce);
    // Ten removed, six of them the cap's orphans, so four were repairs.
    expect(text).toContain("4 objects repaired away as malformed or duplicated");
    expect(text).toContain("6 indicators over the export's total cap");
    expect(text).toContain("6 relationships left pointing at a capped indicator");
    expect(text).toContain("27 references trimmed from a report or a note");
  });

  it("draws the cap alone on a bundle the pass had nothing to repair", () => {
    const text = bundleLossSentence(SHAPES.benign);
    expect(text).not.toContain("repaired away");
    expect(text).toContain("6 indicators over the export's total cap");
    expect(text).toContain("12 references trimmed");
  });

  it("draws the repair alone where nothing was capped", () => {
    const malformed = bundleLossSentence(SHAPES.malformed);
    expect(malformed).toContain("1 object repaired away");
    expect(malformed).toContain("2 references trimmed");
    expect(malformed).not.toContain("total cap");

    const duplicates = bundleLossSentence(SHAPES.duplicates);
    expect(duplicates).toContain("7 objects repaired away");
    expect(duplicates).not.toContain("references trimmed");

    const dangling = bundleLossSentence(SHAPES.dangling);
    expect(dangling).toContain("1 object repaired away");
  });

  it("draws a report that kept every object and lost references", () => {
    const text = bundleLossSentence(SHAPES.overTheCapWithAReport);
    expect(text).toContain("30 references trimmed from a report or a note");
  });

  it("agrees its nouns with the count", () => {
    expect(bundleLossSentence({ indicator_cap_removed: 1 })).toContain("1 indicator over");
    expect(bundleLossSentence({ integrity_objects_removed: 1 })).toContain("1 object repaired");
    expect(bundleLossSentence({ integrity_refs_trimmed: 1 })).toContain("1 reference trimmed");
    expect(
      bundleLossSentence({ integrity_objects_removed: 1, integrity_dropped: { cap_orphan: 1 } }),
    ).toContain("1 relationship left pointing");
  });
});
