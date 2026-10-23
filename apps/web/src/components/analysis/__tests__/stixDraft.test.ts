import { describe, expect, it } from "vitest";

import {
  NAVIGATOR_LAYER_FILE,
  STIX_DRAFT_FILE,
  STIX_EXPORT_FILE,
  readStixAnswer,
} from "@/components/analysis/stixGraph";

describe("readStixAnswer", () => {
  it("reads the API envelope of a draft and unwraps its bundle", () => {
    const bundle = { type: "bundle", objects: [] };
    const answer = readStixAnswer({ published: false, notice: "a draft", bundle });
    expect(answer).toEqual({ bundle, draft: true, notice: "a draft" });
  });

  it("reads a stored bundle's own flag", () => {
    const stored = { type: "bundle", x_maljan_published: false, x_maljan_notice: "stored draft" };
    const answer = readStixAnswer(stored);
    expect(answer.draft).toBe(true);
    expect(answer.notice).toBe("stored draft");
    expect(answer.bundle).toBe(stored);
  });

  it("reads an export as an export", () => {
    const exported = { type: "bundle", objects: [] };
    expect(readStixAnswer(exported)).toEqual({ bundle: exported, draft: false, notice: null });
    expect(readStixAnswer(null).draft).toBe(false);
  });

  it("names a draft's download apart from the export's", () => {
    expect(STIX_DRAFT_FILE).toBe("maljan-stix-bundle-draft.json");
    expect(STIX_EXPORT_FILE).not.toBe(STIX_DRAFT_FILE);
  });

  it("names the Navigator layer's download apart from both bundles", () => {
    expect(NAVIGATOR_LAYER_FILE).toBe("maljan-attack-layer.json");
    expect([STIX_EXPORT_FILE, STIX_DRAFT_FILE]).not.toContain(NAVIGATOR_LAYER_FILE);
  });
});
