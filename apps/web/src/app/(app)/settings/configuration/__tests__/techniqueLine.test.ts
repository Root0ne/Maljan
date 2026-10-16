import { describe, expect, it } from "vitest";

import schema from "@/test-fixtures/settings-schema.json";
import type { AgentDefinitionEntry, CatalogEntry } from "@/types/settings";
import { withTechniqueLine } from "../AgentDefinitionsEditor";
import { displayedDefinitions, stagedDefinitions } from "../agentStaging";
import { describeChange } from "../describeChange";
import { buildImportPreview } from "../importPreview";

/** The served agent definitions' entry (the served-schema fixture). */
function definitionsEntry(): CatalogEntry {
  for (const group of (schema as unknown as { groups: { entries: CatalogEntry[] }[] }).groups) {
    for (const entry of group.entries) {
      if (entry.editor === "agent_definitions") return entry;
    }
  }
  throw new Error("no agent_definitions entry in the served schema");
}

const base: AgentDefinitionEntry = {
  role: "generic",
  label: "Checker",
  prompt: "p",
  tools: [],
  static_provider: null,
  enabled: true,
  max_steps: null,
  timeout_seconds: null,
};

describe("the ATT&CK technique line through staging", () => {
  it("draws a stored off turned back on as on, the way the settings model stores it", () => {
    const saved = { checker: { ...base, attck_techniques: false } };
    const next = { ...saved, checker: withTechniqueLine(saved.checker, true) };
    const shown = displayedDefinitions(stagedDefinitions(next, saved), saved);
    expect(shown.checker.attck_techniques).toBeUndefined();
    expect(shown.checker.attck_techniques !== false).toBe(true);
  });

  it("draws a stored on turned off as off", () => {
    const saved = { checker: base };
    const next = { ...saved, checker: withTechniqueLine(base, false) };
    const shown = displayedDefinitions(stagedDefinitions(next, saved), saved);
    expect(shown.checker.attck_techniques).toBe(false);
  });

  it("still draws a built-in's narrowed staging over its stored entry", () => {
    const stat: AgentDefinitionEntry = { ...base, role: "static", label: "Static analyst" };
    const saved = { static: stat };
    const next = { static: { ...stat, enabled: false } };
    const shown = displayedDefinitions(stagedDefinitions(next, saved), saved);
    expect(shown.static).toEqual({ ...stat, enabled: false });
  });
});

describe("the ATT&CK technique line in the review and the import preview", () => {
  const entry = definitionsEntry();

  it("reads an explicit on as no field: no change", () => {
    const line = describeChange(
      entry,
      { checker: base },
      { checker: { ...base, attck_techniques: true } }
    );
    expect(line.detail).toBeUndefined();
  });

  it("names a switch turned off", () => {
    const line = describeChange(
      entry,
      { checker: base },
      { checker: { ...base, attck_techniques: false } }
    );
    expect(line.detail).toEqual(["checker: changed: ATT&CK technique line"]);
  });

  it("previews an import that writes the switch on as no change", () => {
    const preview = buildImportPreview(
      {
        format: "maljan-settings/1",
        values: { [entry.key]: { checker: { ...base, attck_techniques: true } } },
      },
      { [entry.key]: entry },
      { [entry.key]: { checker: base } }
    );
    expect(preview.lines).toEqual([]);
    expect(preview.errors).toEqual({});
  });

  it("previews an import that turns the switch off as that change", () => {
    const preview = buildImportPreview(
      {
        format: "maljan-settings/1",
        values: { [entry.key]: { checker: { ...base, attck_techniques: false } } },
      },
      { [entry.key]: entry },
      { [entry.key]: { checker: base } }
    );
    expect(preview.lines.map((l) => l.detail)).toEqual([
      ["checker: changed: ATT&CK technique line"],
    ]);
  });
});
