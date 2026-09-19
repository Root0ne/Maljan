import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  bundleLossSentence,
  corpusHeldSentence,
  partialGroundingSentence,
} from "@/lib/report-utils";

/**
 * The shared fixture the report builds the same sentence from. One reading,
 * two surfaces: the report printed `integrity_objects_removed` as "repaired
 * away" with the cap's orphaned relationships inside it and said 10 where this
 * side said 4 about the same run. A change to either wording now fails on the
 * side that was not changed.
 */
const FIXTURE = JSON.parse(
  readFileSync(
    join(__dirname, "../../../../../tests/fixtures/golden/bundle_loss_sentences.json"),
    "utf-8",
  ),
) as {
  cases: Array<{ shape: string; counts: Record<string, unknown>; sentence: string }>;
};

describe("the sentence both surfaces build", () => {
  for (const testCase of FIXTURE.cases) {
    it(`reads the same as the report on: ${testCase.shape}`, () => {
      expect(bundleLossSentence(testCase.counts) ?? "").toBe(testCase.sentence);
    });
  }
});

describe("partialGroundingSentence", () => {
  it("says nothing when the grounding searched the whole record", () => {
    expect(partialGroundingSentence(null)).toBeNull();
    expect(partialGroundingSentence({})).toBeNull();
    expect(partialGroundingSentence({ evidence_corpus_missing_answers: 0 })).toBeNull();
  });

  it("names the reason, the count and the tools", () => {
    const text = partialGroundingSentence({
      evidence_corpus_partial_reason: "ceiling zero",
      evidence_corpus_missing_answers: 3,
      evidence_corpus_missing_tools: ["get_dns", "get_strings"],
    });
    expect(text).toContain("ceiling zero");
    expect(text).toContain("3 answers not kept");
    expect(text).toContain("from get_dns, get_strings");
    expect(text).toContain("a note and drops nothing");
  });

  it("agrees its noun with the count and needs no tool names", () => {
    const text = partialGroundingSentence({
      evidence_corpus_partial_reason: "run resumed without its corpus",
      evidence_corpus_missing_answers: 1,
    });
    expect(text).toContain("1 answer not kept.");
  });
});



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

describe("corpusHeldSentence", () => {
  it("says nothing for a run that recorded nothing about what it held", () => {
    expect(corpusHeldSentence(null)).toBeNull();
    expect(corpusHeldSentence({})).toBeNull();
    expect(corpusHeldSentence({ evidence_corpus_answers: 12 })).toBeNull();
  });

  it("carries a corpus with room to spare silently", () => {
    expect(
      corpusHeldSentence({
        evidence_corpus_answers: 12,
        evidence_corpus_bytes_held: 1000,
        evidence_corpus_bytes_ceiling: 16777216,
      }),
    ).toBeNull();
  });

  it("says what a corpus past half its ceiling held", () => {
    expect(
      corpusHeldSentence({
        evidence_corpus_answers: 12,
        evidence_corpus_bytes_held: 600,
        evidence_corpus_bytes_ceiling: 1000,
      }),
    ).toBe("The grounding corpus held 12 answers, 600 of 1000 bytes.");
  });

  it("says what a partial corpus held, however small", () => {
    expect(
      corpusHeldSentence({
        evidence_corpus_answers: 1,
        evidence_corpus_bytes_held: 4,
        evidence_corpus_bytes_ceiling: 1000,
        evidence_corpus_partial_reason: "ceiling reached",
      }),
    ).toBe("The grounding corpus held 1 answer, 4 of 1000 bytes.");
  });
});
