import { describe, expect, it } from "vitest";
import { enrichMessage } from "@/lib/enrichment";

describe("enrich status message (WA-L9)", () => {
  it("names the known statuses", () => {
    expect(enrichMessage("already_queued")).toMatch(/already running/);
    expect(enrichMessage("skipped_no_network_iocs")).toMatch(/No network IOCs/);
  });
  it("does not call an unknown status queued", () => {
    const text = enrichMessage("something_new");
    expect(text).not.toMatch(/queued/i);
    expect(text).toContain("something_new");
  });
  it("says a missing status as missing", () => {
    expect(enrichMessage(undefined)).toMatch(/no status/i);
  });
});
