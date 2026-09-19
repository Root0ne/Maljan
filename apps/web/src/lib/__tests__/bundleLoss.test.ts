import { describe, expect, it } from "vitest";

import { bundleLossSentence } from "@/lib/report-utils";

describe("bundleLossSentence", () => {
  it("says nothing when the bundle kept everything", () => {
    expect(bundleLossSentence(null)).toBeNull();
    expect(
      bundleLossSentence({ integrity_objects_removed: 0, indicator_cap_removed: 0 }),
    ).toBeNull();
  });

  it("says nothing for a summary stored before the counters existed", () => {
    expect(bundleLossSentence({})).toBeNull();
  });

  it("names the repair and the cap separately", () => {
    const text = bundleLossSentence({
      integrity_objects_removed: 4,
      indicator_cap_removed: 5,
    });
    expect(text).toContain("4 objects repaired away");
    expect(text).toContain("5 indicators over the export's total cap");
  });

  it("agrees its nouns with the count", () => {
    expect(bundleLossSentence({ indicator_cap_removed: 1 })).toContain("1 indicator over");
    expect(bundleLossSentence({ integrity_objects_removed: 1 })).toContain("1 object repaired");
  });

  it("states only the bound that fired", () => {
    const capped = bundleLossSentence({ indicator_cap_removed: 2 });
    expect(capped).not.toContain("repaired away");
    const repaired = bundleLossSentence({ integrity_objects_removed: 2 });
    expect(repaired).not.toContain("total cap");
  });
});
