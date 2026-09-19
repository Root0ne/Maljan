import { describe, expect, it } from "vitest";

import { isAdvisory, isExportDecision, validationRowText } from "@/lib/validationRows";

/**
 * Who a run's unresolved rows say acted.
 *
 * The Run record drew every row as "{agent} left {code} unfixed". For a
 * producer that was corrected and answered the same way twice, that is the
 * truth. For a row about the export it is the opposite of it: the judge wrote a
 * malware object beside an assessment calling the sample benign, and the export
 * declined to carry it — the judge did not leave anything unfixed there.
 */
describe("what an unresolved row says", () => {
  it("names the export for a decision the export made", () => {
    const text = validationRowText({
      agent: "judge",
      code: "stix.malware_object_under_benign",
      message: "the malware object 'PuTTY' is not in the exported bundle.",
    });

    expect(text).toContain("the export did not publish");
    expect(text).not.toContain("left");
    expect(text).toContain("the malware object 'PuTTY' is not in the exported bundle.");
  });

  it("says the same for an endpoint no host question could pass", () => {
    expect(
      validationRowText({
        agent: "judge",
        code: "stix.unpublishable_endpoint",
        message: "its host is not a name or address that could exist.",
      }),
    ).toMatch(/^the export did not publish stix\.unpublishable_endpoint:/);
  });

  it("reads the two codes a stored run carries as the same decision", () => {
    // One question under two names, with the second of them covering addresses
    // too. Nothing is migrated, so a run recorded before the rename keeps the
    // row it wrote and is drawn with the same sentence.
    for (const code of ["stix.unpublishable_url", "stix.unpublishable_domain"]) {
      expect(isExportDecision(code)).toBe(true);
      expect(
        validationRowText({
          agent: "judge",
          code,
          message: "it is not a name or address that could exist.",
        }),
      ).toBe(
        `the export did not publish ${code}: it is not a name or address that could exist.`,
      );
    }
  });

  it("says the same for an artefact and for a digest the export refused", () => {
    expect(isExportDecision("stix.unpublishable_artefact")).toBe(true);
    expect(isExportDecision("stix.malformed_hash")).toBe(true);
  });

  it("says the same for an annotation that went with a rejected technique", () => {
    expect(isExportDecision("stix.unlinked_technique")).toBe(true);
  });

  it("leaves a producer's own surviving violation as it was", () => {
    const text = validationRowText({
      agent: "judge",
      code: "verdict.assessment_conflict",
      message: "those are two different answers about the same sample.",
    });

    expect(text).toBe(
      "judge left verdict.assessment_conflict unfixed: those are two different answers " +
        "about the same sample.",
    );
  });

  it("leaves an indicator the judge was asked about and kept", () => {
    /* Also a `stix.` code, and genuinely the judge's to have fixed. */
    expect(isExportDecision("stix.ungrounded_indicator")).toBe(false);
    expect(
      validationRowText({ agent: "judge", code: "stix.ungrounded_indicator", message: "x" }),
    ).toBe("judge left stix.ungrounded_indicator unfixed: x");
  });

  it("leaves an analyst's own row alone", () => {
    expect(
      validationRowText({ agent: "static", code: "attck.unknown_id", message: "no entry" }),
    ).toBe("static left attck.unknown_id unfixed: no entry");
  });
});

describe("an advisory row", () => {
  it("is read from the string the wire carries", () => {
    expect(isAdvisory({ advisory: "true" })).toBe(true);
    expect(isAdvisory({ advisory: true })).toBe(true);
    expect(isAdvisory({})).toBe(false);
    expect(isAdvisory({ advisory: "" })).toBe(false);
  });

  it("is not drawn as a producer's unfixed finding", () => {
    const text = validationRowText({
      agent: "judge",
      code: "stix.ungrounded_indicator",
      message: "gate.example.org appears nowhere in the evidence this run collected.",
      advisory: "true",
    });

    expect(text).toContain("nothing dropped");
    expect(text).not.toContain("left stix.ungrounded_indicator unfixed");
  });

  it("leaves an ordinary row reading as it did", () => {
    const text = validationRowText({
      agent: "static",
      code: "isr.confidence_range",
      message: "a confidence outside 0..1",
    });

    expect(text).toBe("static left isr.confidence_range unfixed: a confidence outside 0..1");
  });
});
