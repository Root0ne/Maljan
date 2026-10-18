/**
 * A stored value `GET /settings` could not serve: the row says why.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { SettingValue } from "@/types/settings";
import StoredValueRefusedNote, { unreadableNote } from "../StoredValueRefusedNote";

const REASON =
  "the stored value is not served: the answer's writer refused it " +
  "(ValueError: Circular reference detected (depth exceeded)); reset this key or save it again";

const unserved: SettingValue = {
  value: null,
  is_set: null,
  hint: null,
  source: "ui",
  updated_at: null,
  updated_by: null,
  unreadable: REASON,
};

describe("a stored value the API did not serve", () => {
  it("is said with the API's reason", () => {
    expect(unreadableNote(unserved)).toBe(`The stored value is not shown: ${REASON}.`);
  });

  it("says nothing for a served value", () => {
    expect(unreadableNote({ ...unserved, value: 1, unreadable: null })).toBe("");
    expect(unreadableNote({ ...unserved, unreadable: undefined })).toBe("");
    expect(unreadableNote(undefined)).toBe("");
  });

  it("is drawn on the row", () => {
    const html = renderToStaticMarkup(
      createElement(StoredValueRefusedNote, { settingKey: "core.llm.provider", current: unserved })
    );
    expect(html).toContain("data-stored-value-unreadable");
    expect(html).toContain("the answer&#x27;s writer refused it");
    expect(renderToStaticMarkup(createElement(StoredValueRefusedNote, { settingKey: "k" }))).toBe("");
  });
});
