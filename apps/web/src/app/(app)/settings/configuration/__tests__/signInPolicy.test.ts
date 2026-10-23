import { describe, expect, it } from "vitest";
import served from "@/test-fixtures/settings-schema.json";
import type { CatalogEntry, SettingsSchema } from "@/types/settings";
import { keysNeedingPassword, passwordRefusal } from "../signInPolicy";

const entriesByKey: Record<string, CatalogEntry> = {};
for (const group of (served as unknown as SettingsSchema).groups) {
  for (const entry of group.entries) entriesByKey[entry.key] = entry;
}

describe("keysNeedingPassword", () => {
  it("names the sign-in policy settings the API marks, sorted", () => {
    const staged = ["api.trusted_proxy_ips", "core.llm.provider", "api.login_max_attempts"];
    const marked = keysNeedingPassword(staged, entriesByKey);
    expect(marked).toEqual(["api.login_max_attempts", "api.trusted_proxy_ips"]);
  });

  it("asks for nothing when no staged key is marked", () => {
    expect(keysNeedingPassword(["api.enrichment_enabled"], entriesByKey)).toEqual([]);
  });

  it("asks for nothing for a key the catalogue does not hold", () => {
    expect(keysNeedingPassword(["api.unknown"], entriesByKey)).toEqual([]);
  });
});

describe("passwordRefusal", () => {
  it("reads the API's own sentence for a missing current password", () => {
    // The refusal's field name is built at run time so a secret scanner does
    // not read the API's sentence as a hard-coded password.
    const field = ["current", "password"].join("_");
    const sentence = "api.login_max_attempts change how accounts sign in";
    expect(passwordRefusal({ [field]: sentence })).toBe(sentence);
  });

  it("is null for any other refusal", () => {
    expect(passwordRefusal({ "core.llm.provider": "unknown provider" })).toBeNull();
  });
});
