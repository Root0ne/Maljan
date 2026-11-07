import { describe, expect, it } from "vitest";

import {
  NAVIGATOR_LAYER_FILE,
  STIX_DRAFT_FILE,
  STIX_EXPORT_FILE,
  evidenceIdsOf,
  readStixAnswer,
  statedConfidence,
} from "@/components/analysis/stixGraph";
import { PREVIOUS_PROPERTY_PREFIX } from "@/lib/previousName";

describe("readStixAnswer", () => {
  it("reads the API envelope of a draft and unwraps its bundle", () => {
    const bundle = { type: "bundle", objects: [] };
    const answer = readStixAnswer({ published: false, notice: "a draft", bundle });
    expect(answer).toEqual({ bundle, draft: true, notice: "a draft" });
  });

  it("reads a stored bundle's own flag", () => {
    const stored = { type: "bundle", x_malspark_published: false, x_malspark_notice: "stored draft" };
    const answer = readStixAnswer(stored);
    expect(answer.draft).toBe(true);
    expect(answer.notice).toBe("stored draft");
    expect(answer.bundle).toBe(stored);
  });

  it("reads a draft stored before the rename as a draft", () => {
    const stored = {
      type: "bundle",
      [`${PREVIOUS_PROPERTY_PREFIX}published`]: false,
      [`${PREVIOUS_PROPERTY_PREFIX}notice`]: "stored draft",
    };
    const answer = readStixAnswer(stored);
    expect(answer.draft).toBe(true);
    expect(answer.notice).toBe("stored draft");
  });

  it("reads an object's confidence and evidence stored before the rename", () => {
    const stored = {
      [`${PREVIOUS_PROPERTY_PREFIX}confidence`]: 0.8,
      [`${PREVIOUS_PROPERTY_PREFIX}evidence_refs`]: ["ev_0001"],
    };
    expect(statedConfidence(stored)).toEqual({ value: 0.8, property: "x_malspark_confidence" });
    expect(evidenceIdsOf(stored)).toEqual(["ev_0001"]);
  });

  it("reads an export as an export", () => {
    const exported = { type: "bundle", objects: [] };
    expect(readStixAnswer(exported)).toEqual({ bundle: exported, draft: false, notice: null });
    expect(readStixAnswer(null).draft).toBe(false);
  });

  it("names a draft's download apart from the export's", () => {
    expect(STIX_DRAFT_FILE).toBe("malspark-stix-bundle-draft.json");
    expect(STIX_EXPORT_FILE).not.toBe(STIX_DRAFT_FILE);
  });

  it("names the Navigator layer's download apart from both bundles", () => {
    expect(NAVIGATOR_LAYER_FILE).toBe("malspark-attack-layer.json");
    expect([STIX_EXPORT_FILE, STIX_DRAFT_FILE]).not.toContain(NAVIGATOR_LAYER_FILE);
  });
});
