import { describe, expect, it } from "vitest";
import { seededProfiles } from "@/app/(app)/settings/configuration/seededProfiles";

describe("seeded teams come from the catalog default (WA-L7)", () => {
  it("names the keys of the default", () => {
    const set = seededProfiles({ default: {}, new_team: {} });
    expect(set.has("new_team")).toBe(true);
    expect(set.has("mobile")).toBe(false);
  });
  it("falls back to the five seeded teams when the API served no usable default", () => {
    for (const none of [undefined, null, {}, [], "x"]) {
      const set = seededProfiles(none);
      expect([...set].sort()).toEqual(["deep_static", "default", "measurement", "mobile", "team_lead"]);
    }
  });
});
