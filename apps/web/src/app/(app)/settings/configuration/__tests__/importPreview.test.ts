import { describe, expect, it } from "vitest";
import { buildImportPreview, type ImportDoc } from "../importPreview";
import type { CatalogEntry } from "@/types/settings";

function entry(overrides: Partial<CatalogEntry>): CatalogEntry {
  return {
    key: "core.test.leaf",
    namespace: "core",
    path: "test.leaf",
    type: "str",
    default: null,
    nullable: true,
    choices: null,
    minimum: null,
    maximum: null,
    secret: false,
    group: "test",
    title: "Test leaf",
    description: "",
    applies: "next_job",
    editable: true,
    reason: null,
    probe: null,
    applies_when: null,
    order: 0,
    choices_from: null,
    editor: null,
    subgroup: null,
    advanced: false,
    ...overrides,
  };
}

const knownEntry = entry({ key: "core.negotiation.retry_delay", type: "int", title: "Retry delay" });
const readOnlyEntry = entry({ key: "core.deploy.host", type: "str", title: "Host", editable: false });
const secretEntry = entry({ key: "core.llm.openai.api_key", type: "secret", title: "OpenAI API key", secret: true });

const entriesByKey: Record<string, CatalogEntry> = {
  [knownEntry.key]: knownEntry,
  [readOnlyEntry.key]: readOnlyEntry,
  [secretEntry.key]: secretEntry,
};

function doc(values: Record<string, unknown>, format = "maljan-settings/1"): ImportDoc {
  return { format, values };
}

describe("buildImportPreview", () => {
  it("lines a known editable key whose imported value differs from the current one", () => {
    const result = buildImportPreview(
      doc({ [knownEntry.key]: 20 }),
      entriesByKey,
      { [knownEntry.key]: 5 }
    );
    expect(result.errors).toEqual({});
    expect(result.lines).toHaveLength(1);
    expect(result.lines[0]).toMatchObject({ key: knownEntry.key, summary: "5 → 20" });
  });

  it("errors an unknown key", () => {
    const result = buildImportPreview(doc({ "core.no.such.key": 1 }), entriesByKey, {});
    expect(result.lines).toEqual([]);
    expect(result.errors).toEqual({ "core.no.such.key": "unknown key" });
  });

  it("errors a read-only key", () => {
    const result = buildImportPreview(
      doc({ [readOnlyEntry.key]: "new-host" }),
      entriesByKey,
      { [readOnlyEntry.key]: "old-host" }
    );
    expect(result.lines).toEqual([]);
    expect(result.errors).toEqual({ [readOnlyEntry.key]: "read-only" });
  });

  it("errors an unsupported format and skips every value", () => {
    const result = buildImportPreview(
      doc({ [knownEntry.key]: 20 }, "maljan-settings/2"),
      entriesByKey,
      { [knownEntry.key]: 5 }
    );
    expect(result.lines).toEqual([]);
    expect(result.errors).toEqual({ format: "unsupported format" });
  });

  it("does not line an unchanged key", () => {
    const result = buildImportPreview(
      doc({ [knownEntry.key]: 5 }),
      entriesByKey,
      { [knownEntry.key]: 5 }
    );
    expect(result.lines).toEqual([]);
    expect(result.errors).toEqual({});
  });

  it("always lines a secret as '(secret) will be set', never the value", () => {
    const result = buildImportPreview(
      doc({ [secretEntry.key]: "sk-super-secret" }),
      entriesByKey,
      { [secretEntry.key]: null }
    );
    expect(result.lines).toHaveLength(1);
    expect(result.lines[0].summary).toBe("(secret) will be set");
    expect(JSON.stringify(result.lines)).not.toContain("sk-super-secret");
  });
});
