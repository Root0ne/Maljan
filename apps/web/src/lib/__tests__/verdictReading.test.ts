import { describe, expect, it } from "vitest";

import { degradedBannerText } from "@/lib/degradedBanner";
import { verdictReadingNote } from "@/lib/verdictHeader";
import type { VerdictReading } from "@/lib/api";

/**
 * How a run's verdict was arrived at, said on the two surfaces a reader opens.
 *
 * Three of the four readings publish the inconclusive verdict, which is one of
 * the same three words a judge may state — so `Suspicious` alone cannot be
 * read. The markdown report has carried the sentence since the reading
 * existed; the console drew the word and, in its degraded banner, asserted
 * that the confidence beside it was the judge's own, which on those three
 * paths is exactly what it is not.
 */

const READINGS: VerdictReading[] = ["stated", "unrecognised", "unstated", "fallback"];

describe("the note beside the verdict", () => {
  it("says nothing for a verdict the judge stated", () => {
    expect(verdictReadingNote("stated")).toBeNull();
  });

  it("says nothing for a report stored before the reading existed", () => {
    expect(verdictReadingNote(null)).toBeNull();
    expect(verdictReadingNote(undefined)).toBeNull();
  });

  it("says the verdict is not the judge's when its answer could not be read", () => {
    const note = verdictReadingNote("unrecognised");

    expect(note).toContain("could not read as a verdict");
    expect(note).toContain("not the judge's");
    expect(note).toContain("no confidence");
  });

  it("says where the verdict came from when the judge stated none", () => {
    const note = verdictReadingNote("unstated");

    expect(note).toContain("stated no verdict");
    expect(note).toContain("objects");
  });

  it("says so when the judge did not answer with a bundle", () => {
    expect(verdictReadingNote("fallback")).toContain("did not answer with a bundle");
  });

  it("is a sentence rather than a colour on every reading it draws", () => {
    for (const reading of READINGS) {
      const note = verdictReadingNote(reading);
      if (note === null) continue;
      expect(note.length).toBeGreaterThan(40);
      expect(note.endsWith(".")).toBe(true);
    }
  });
});

describe("the degraded banner", () => {
  it("claims the confidence is the judge's only when it is", () => {
    expect(degradedBannerText("stated", 0.9)).toContain("the judge's own");
  });

  it("never claims it on a reading the judge did not make", () => {
    for (const reading of ["unrecognised", "unstated", "fallback"] as VerdictReading[]) {
      const text = degradedBannerText(reading, null);
      expect(text).not.toContain("the judge's own");
      expect(text).toContain("no confidence is published");
    }
  });

  it("keeps the sentence the banner opens with, whatever the reading", () => {
    for (const reading of READINGS) {
      expect(degradedBannerText(reading, null)).toContain("only partial signal");
    }
  });

  it("describes no confidence when the judge stated a verdict and put no number on it", () => {
    // The judge is allowed to answer `Benign` and assess no confidence, and
    // the header then reads "not assessed". A banner describing the
    // confidence shown above would be describing nothing.
    const text = degradedBannerText("stated", null);

    expect(text).not.toContain("the judge's own");
    expect(text).toContain("No confidence was assessed");
  });

  it("reads a report with no recorded reading off its confidence", () => {
    expect(degradedBannerText(null, 0.9)).toContain("the judge's own");
    expect(degradedBannerText(null, null)).toContain("No confidence was assessed");
    expect(degradedBannerText(undefined, null)).not.toContain("the judge's own");
  });
});
