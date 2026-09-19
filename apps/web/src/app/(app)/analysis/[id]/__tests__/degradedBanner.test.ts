/* The DEGRADED RUN banner must not describe a cap that no longer exists.
 *
 * The pipeline used to pull a degraded run's confidence down to a fixed 0.60
 * and this banner said so. Nothing caps anything now — the judge is told why
 * the run is thin and sets its own number — so the sentence was false on the
 * most-read surface in the product, and the condition it hung on made it
 * appear precisely on the runs whose confidence was highest.
 *
 * The page is a React server component with a full data layer behind it, so
 * this reads its source rather than rendering it: what is being pinned is the
 * absence of a claim, and a claim that is absent from the source cannot reach
 * a reader however the component is mounted.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const PAGE = readFileSync(path.resolve(__dirname, "../page.tsx"), "utf8");

describe("the degraded-run banner", () => {
  it("never tells the reader the confidence was capped", () => {
    for (const claim of ["capped", "capping", "CONFIDENCE_CAP"]) {
      expect(PAGE).not.toContain(claim);
    }
  });

  it("still names the run as degraded and lists the reasons", () => {
    expect(PAGE).toContain("DEGRADED RUN");
    expect(PAGE).toContain("degradationReasons");
  });

  it("leaves the sentence about the confidence to the reading it was read under", () => {
    // A run whose verdict the judge did not state, or stated in a word the
    // pipeline does not know, publishes no confidence of the judge's, so the
    // page cannot say the number above the banner is the judge's own. Which
    // sentence is true is decided by degradedBannerText from the recorded
    // reading; the wordings themselves are pinned beside that function.
    expect(PAGE).toContain("degradedBannerText");
    expect(PAGE).not.toContain("the judge&apos;s own");
  });
});
