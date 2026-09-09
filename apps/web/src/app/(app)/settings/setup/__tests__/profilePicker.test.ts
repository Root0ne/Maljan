import { describe, expect, it } from "vitest";
import type { ProfileEntry } from "@/types/settings";

import { withAgentInProfile, withoutProfile } from "../steps/profilePicker";

const profiles = (): Record<string, ProfileEntry> => ({
  default: { label: "Default", analysts: ["static", "dynamic"] },
  quick: { label: "", analysts: ["static"] },
});

describe("withAgentInProfile", () => {
  it("appends the agent to an existing profile, keeping its label", () => {
    const next = withAgentInProfile(profiles(), "quick", "yara");
    expect(next.quick).toEqual({ label: "", analysts: ["static", "yara"] });
    expect(next.default).toEqual(profiles().default);
  });

  it("does not add the same analyst twice", () => {
    const next = withAgentInProfile(profiles(), "default", "dynamic");
    expect(next.default.analysts).toEqual(["static", "dynamic"]);
  });

  it("creates a missing profile from the named source, with the copy label", () => {
    const next = withAgentInProfile(profiles(), "triage", "yara", "default");
    expect(next.triage).toEqual({
      label: "Default (copy)",
      analysts: ["static", "dynamic", "yara"],
    });
    expect(Object.keys(next)).toEqual(["default", "quick", "triage"]);
  });

  it("names a copy of an unlabelled source after the new key", () => {
    expect(withAgentInProfile(profiles(), "triage", "yara", "quick").triage).toEqual({
      label: "triage",
      analysts: ["static", "yara"],
    });
  });

  it("creates a profile of just the agent when there is no source", () => {
    expect(withAgentInProfile(profiles(), "solo", "yara").solo).toEqual({
      label: "solo",
      analysts: ["yara"],
    });
  });

  it("leaves the map it was given alone", () => {
    const before = profiles();
    withAgentInProfile(before, "quick", "yara");
    expect(before).toEqual(profiles());
  });
});

describe("withoutProfile", () => {
  it("drops only the named profile", () => {
    expect(withoutProfile(profiles(), "quick")).toEqual({ default: profiles().default });
  });

  it("is a no-op for a profile that is not there", () => {
    expect(withoutProfile(profiles(), "nope")).toEqual(profiles());
  });
});
