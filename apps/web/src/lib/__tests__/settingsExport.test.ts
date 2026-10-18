/**
 * After an export, the toolbar names the keys the document left out under
 * `unreadable`, with why; an export that left nothing out says nothing more.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import { exportLeftOutNotice, exportUnreadable } from "@/lib/settingsExport";

const REASON = "the stored value is not served: the answer's writer refused it (ValueError: x)";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the keys an export left out", () => {
  it("are read from the document", () => {
    const doc = { format: "maljan-settings/2", values: {}, unreadable: { "core.k": REASON } };
    expect(exportUnreadable(JSON.stringify(doc))).toEqual({ "core.k": REASON });
    expect(exportUnreadable(JSON.stringify({ values: {} }))).toEqual({});
    expect(exportUnreadable("not json")).toEqual({});
  });

  it("are named with why", () => {
    expect(exportLeftOutNotice({ "core.k": REASON })).toBe(
      `The export left out 1 stored value it could not write: core.k (${REASON}).`
    );
    expect(exportLeftOutNotice({ a: "x", b: "y" })).toBe(
      "The export left out 2 stored values it could not write: a (x); b (y)."
    );
    expect(exportLeftOutNotice({})).toBe("");
    expect(exportLeftOutNotice(undefined)).toBe("");
  });

  it("come back from the export call", async () => {
    const doc = { format: "maljan-settings/2", values: {}, unreadable: { "core.k": REASON } };
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(doc))));
    const created = vi.fn(() => "blob:x");
    vi.stubGlobal("URL", { ...URL, createObjectURL: created, revokeObjectURL: vi.fn() });
    const anchor = { click: vi.fn(), href: "", download: "" };
    vi.stubGlobal("document", {
      createElement: () => anchor,
      body: { appendChild: vi.fn(), removeChild: vi.fn() },
    });
    expect(await api.exportSettings()).toEqual({ "core.k": REASON });
    expect(anchor.click).toHaveBeenCalled();
  });
});
