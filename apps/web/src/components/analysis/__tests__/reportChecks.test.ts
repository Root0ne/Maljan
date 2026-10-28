import { readFileSync } from "node:fs";
import { join } from "node:path";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { ClaimNotDiscussed, MalwareReport } from "@/types/malware-report";
import ReportChecks from "../ReportChecks";
import {
  ABSENCE_TECHNIQUE_MARKER,
  UNVERIFIED_TECHNIQUE_MARKER,
  claimTechniques,
} from "../reportProse";
import { UNDISCUSSED } from "./storedRunShapes";

/** The two technique notes as the report prints them, pinned for both surfaces. */
const MARKERS = JSON.parse(
  readFileSync(
    join(__dirname, "../../../../../../tests/fixtures/golden/technique_markers.json"),
    "utf-8",
  ),
) as { unverified: string; absence_kept: string };

/** One block listing three techniques, stored as one claim with all of them (T-406). */
const SPLIT: ClaimNotDiscussed = {
  agent: "static",
  claim_number: 1,
  claim: "Routine 0x7fa8 calls GetComputerNameExA for the host.",
  confidence: 0.9,
  missing: ["GetComputerNameExA"],
  technique_ids: ["T1082", "T1016", "T1033"],
  unverified_technique_ids: ["T1016"],
  absence_kept_technique_ids: ["T1033"],
};

const render = (claims: ClaimNotDiscussed[]) =>
  renderToStaticMarkup(
    createElement(ReportChecks, { mr: { claims_not_discussed: claims } as MalwareReport }),
  );

describe("a claim's techniques in the claims the report does not discuss (T-424)", () => {
  it("carry the notes the report prints, word for word", () => {
    expect(UNVERIFIED_TECHNIQUE_MARKER).toBe(MARKERS.unverified);
    expect(ABSENCE_TECHNIQUE_MARKER).toBe(MARKERS.absence_kept);
  });

  it("are written as the report's section 13.1 writes them, each with its note", () => {
    expect(claimTechniques(SPLIT)).toBe(
      `techniques T1082, T1016 (${UNVERIFIED_TECHNIQUE_MARKER}), T1033 (${ABSENCE_TECHNIQUE_MARKER})`,
    );
    expect(claimTechniques({ ...SPLIT, technique_ids: ["T1057"] })).toBe("technique T1057");
  });

  it("are nothing for a claim stored before the field existed", () => {
    expect(claimTechniques(UNDISCUSSED[0])).toBe("");
  });

  it("are drawn once with the claim, a split claim listed once", () => {
    const html = render([
      SPLIT,
      {
        agent: "static",
        claim_number: 2,
        claim: "Walks the process list.",
        technique_ids: ["T1057"],
      },
    ]);

    expect(html.match(/<li/g)).toHaveLength(2);
    expect(html).toContain(
      "(techniques T1082, T1016 (technique id not in the ATT&amp;CK catalog), " +
        `T1033 (${ABSENCE_TECHNIQUE_MARKER}))`,
    );
    expect(html).toContain("(technique T1057)");
    expect(html.match(/T1082/g)).toHaveLength(1);
  });

  it("leave a stored claim without techniques drawn as before", () => {
    const html = render(UNDISCUSSED);

    expect(html).not.toContain("technique");
    expect(html).toContain("static #2");
  });
});
