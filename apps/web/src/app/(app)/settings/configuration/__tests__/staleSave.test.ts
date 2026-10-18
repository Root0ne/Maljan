/**
 * A save over a value changed since the page loaded it: the PATCH carries the
 * versions the page was served, a 409 arrives as a `SettingsConflictError`,
 * and the page says which keys and that nothing was saved.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import {
  SettingsConflictError,
  SettingsValidationError,
  type SettingValue,
} from "@/types/settings";
import { conflictMessage, loadedVersions } from "../useSettings";

const served = (updated_at: string | null): SettingValue => ({
  value: 1,
  is_set: null,
  hint: null,
  source: updated_at ? "ui" : "default",
  updated_at,
  updated_by: null,
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the versions a save carries", () => {
  it("names each staged key the page was served, with the version it was served", () => {
    const values = {
      "core.sandbox.report_formats": served("2026-01-02T03:04:05.678901Z"),
      "core.llm.expert_max_tokens": served(null),
      "core.not.staged": served("2026-01-02T03:04:05Z"),
    };
    const pending = {
      "core.sandbox.report_formats": [],
      "core.llm.expert_max_tokens": 2048,
      "core.never.served": 1,
    };
    expect(loadedVersions(pending, values)).toEqual({
      "core.sandbox.report_formats": "2026-01-02T03:04:05.678901Z",
      "core.llm.expert_max_tokens": null,
    });
  });

  it("are sent beside the changes", async () => {
    const fetch = vi.fn(async () => new Response(JSON.stringify({ applied: [], applies: {} })));
    vi.stubGlobal("fetch", fetch);
    await api.patchSettings({ k: 1 }, { k: null });
    const init = (fetch.mock.calls[0] as unknown as [string, RequestInit])[1];
    expect(JSON.parse(String(init.body))).toEqual({ changes: { k: 1 }, versions: { k: null } });
  });
});

describe("a save refused over a changed value", () => {
  it("arrives as a conflict carrying each key's reason", async () => {
    const errors = { "core.sandbox.report_formats": "saved again since this page loaded it" };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ errors }), { status: 409 }))
    );
    const refused = await api.patchSettings({ "core.sandbox.report_formats": [] }).catch((e) => e);
    expect(refused).toBeInstanceOf(SettingsConflictError);
    expect(refused).toBeInstanceOf(SettingsValidationError);
    expect(refused.errors).toEqual(errors);
  });

  it("is said with the keys and that nothing was saved", () => {
    expect(conflictMessage(["core.sandbox.report_formats"])).toBe(
      "core.sandbox.report_formats was changed since this page loaded it, so nothing was " +
        "saved. The stored value is shown again; make the change over it and apply."
    );
    expect(conflictMessage(["a", "b"])).toBe(
      "a, b were changed since this page loaded them, so nothing was saved. The stored " +
        "values are shown again; make the change over them and apply."
    );
  });
});
