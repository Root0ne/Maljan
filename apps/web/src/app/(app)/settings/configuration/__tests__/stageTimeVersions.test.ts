import { describe, expect, it } from "vitest";

import type { SettingValue } from "@/types/settings";
import { loadedVersions, withBaseVersion, withoutBaseVersions } from "../useSettings";

const served = (updated_at: string | null): SettingValue => ({
  value: 1,
  is_set: null,
  hint: null,
  source: updated_at ? "ui" : "default",
  updated_at,
  updated_by: null,
});

describe("the version a staged edit is guarded with", () => {
  it("is the one the key had when it was staged, not whatever a reload fetched since", () => {
    const atStage = { "core.a": served("2026-10-01T00:00:00Z") };
    const base = withBaseVersion({}, "core.a", atStage);
    // Another admin saved core.a; a reset elsewhere reloaded the page's values.
    const reloaded = { "core.a": served("2026-10-02T00:00:00Z") };
    expect(loadedVersions({ "core.a": 2 }, reloaded, base)).toEqual({
      "core.a": "2026-10-01T00:00:00Z",
    });
  });

  it("keeps the first staging's version across later edits of the same key", () => {
    let base = withBaseVersion({}, "core.a", { "core.a": served("v1") });
    base = withBaseVersion(base, "core.a", { "core.a": served("v2") });
    expect(base).toEqual({ "core.a": "v1" });
  });

  it("records a key with no stored row as null, and a key never served not at all", () => {
    const values = { "core.a": served(null) };
    expect(withBaseVersion({}, "core.a", values)).toEqual({ "core.a": null });
    expect(withBaseVersion({}, "core.never", values)).toEqual({});
  });

  it("falls back to the served version for a key staged before any was recorded", () => {
    expect(loadedVersions({ "core.b": 1 }, { "core.b": served("v9") }, {})).toEqual({ "core.b": "v9" });
  });

  it("forgets keys that were unstaged, saved or reset", () => {
    const base = { "core.a": "v1", "core.b": "v2" };
    expect(withoutBaseVersions(base, ["core.a"])).toEqual({ "core.b": "v2" });
    expect(withoutBaseVersions(base, ["core.z"])).toBe(base);
  });
});
