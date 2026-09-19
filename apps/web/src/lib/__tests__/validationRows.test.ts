import { describe, expect, it } from "vitest";

import { isExportDecision, validationRowText } from "@/lib/validationRows";

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

  it("says the same for a URL no host could answer for", () => {
    expect(
      validationRowText({
        agent: "judge",
        code: "stix.unpublishable_url",
        message: "its host is not a name or address that could exist.",
      }),
    ).toMatch(/^the export did not publish stix\.unpublishable_url:/);
  });

  it("says the same for a name or address the export held back", () => {
    // Both codes are one decision in two words, and only one of them was on
    // the list: a domain decline read "judge left stix.unpublishable_domain
    // unfixed", blaming the judge for a call the export made about a row a
    // sandbox had written down.
    expect(isExportDecision("stix.unpublishable_domain")).toBe(true);
    expect(
      validationRowText({
        agent: "judge",
        code: "stix.unpublishable_domain",
        message: "it is not a name or address that could exist.",
      }),
    ).toMatch(/^the export did not publish stix\.unpublishable_domain:/);
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
