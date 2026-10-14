import { describe, expect, it } from "vitest";

import schema from "@/test-fixtures/settings-schema.json";
import type { AgentDefinitionEntry, McpServerEntry } from "@/types/settings";
import { displayedDefinitions, stagedDefinitions, type DefinitionMap } from "../agentStaging";
import { sameToolRef } from "../capabilityRefs";
import { SANDBOX_REF, choiceRows, rosterAgentKeys, toggleChoice } from "../choiceRows";
import { putEntry } from "../mapEditorHelpers";

/** One served catalog entry, picked by its editor (the served-schema fixture). */
function served(editor: string): Record<string, unknown> {
  for (const group of (schema as { groups: { entries: Record<string, unknown>[] }[] }).groups) {
    for (const entry of group.entries) {
      if (entry.editor === editor) return entry;
    }
  }
  throw new Error(`no ${editor} entry in the served schema`);
}

/** What a save sends and a reload reads back: the staged map through JSON. */
function saveAndReload(next: DefinitionMap, saved: DefinitionMap): DefinitionMap {
  const wire = JSON.parse(JSON.stringify(stagedDefinitions(next, saved))) as DefinitionMap;
  return displayedDefinitions(null, { ...saved, ...wire });
}

const custom = (over: Partial<AgentDefinitionEntry> = {}): AgentDefinitionEntry => ({
  role: "generic",
  label: "Dropped-file checker",
  prompt: "Check the files the sample drops.",
  tools: [],
  static_provider: null,
  enabled: true,
  max_steps: null,
  timeout_seconds: null,
  ...over,
});

describe("the agent editor's input data and sandbox reference", () => {
  it("offers the input slices the API serves, in their served order", () => {
    const vocabulary = served("agent_definitions").data_source_choices as string[];
    expect(vocabulary).toContain("sandbox.behavior");
    expect(choiceRows(vocabulary, []).map((r) => r.key)).toEqual(vocabulary);
    expect(choiceRows(vocabulary, []).every((r) => r.known)).toBe(true);
  });

  it("saves and reloads both new fields", () => {
    const saved: DefinitionMap = { checker: custom() };
    let next = putEntry<AgentDefinitionEntry>(saved, "checker", {
      data_sources: toggleChoice([], "sandbox.behavior", true),
    });
    next = putEntry<AgentDefinitionEntry>(next, "checker", { tools: [...next.checker.tools, SANDBOX_REF] });

    const reloaded = saveAndReload(next, saved);
    expect(reloaded.checker.data_sources).toEqual(["sandbox.behavior"]);
    expect(reloaded.checker.tools.some((t) => sameToolRef(t, SANDBOX_REF))).toBe(true);
    expect(reloaded.checker.tools).toEqual([{ kind: "sandbox", server: null, name: null }]);

    // Unticking both takes both away again.
    const cleared = putEntry<AgentDefinitionEntry>(reloaded, "checker", {
      data_sources: toggleChoice(reloaded.checker.data_sources ?? [], "sandbox.behavior", false),
      tools: reloaded.checker.tools.filter((t) => !sameToolRef(t, SANDBOX_REF)),
    });
    const again = saveAndReload(cleared, reloaded);
    expect(again.checker.data_sources).toEqual([]);
    expect(again.checker.tools).toEqual([]);
  });

  it("keeps the input slices a JSON import wrote after an unrelated console edit", () => {
    const imported: DefinitionMap = {
      checker: custom({ data_sources: ["sandbox.full", "sample.path"] }),
    };
    const edited = putEntry<AgentDefinitionEntry>(imported, "checker", { label: "Renamed" });
    const reloaded = saveAndReload(edited, imported);
    expect(reloaded.checker.label).toBe("Renamed");
    expect(reloaded.checker.data_sources).toEqual(["sandbox.full", "sample.path"]);
  });

  it("appends a ticked slice and keeps the stored order of the others", () => {
    expect(toggleChoice(["sandbox.full", "sample.path"], "sandbox.network", true)).toEqual([
      "sandbox.full",
      "sample.path",
      "sandbox.network",
    ]);
    expect(toggleChoice(["sandbox.full"], "sandbox.full", true)).toEqual(["sandbox.full"]);
  });

  it("draws a stored slice the served list does not hold, marked", () => {
    const rows = choiceRows(["sample.path"], ["sample.path", "firmware.image"]);
    expect(rows).toEqual([
      { key: "sample.path", known: true },
      { key: "firmware.image", known: false },
    ]);
  });
});

describe("the server map's agent bindings", () => {
  const servedKeys = served("server_map").agent_keys as string[];
  const seeded = served("server_map").builtin_agent_keys as string[];
  const stored = (definitions: Record<string, unknown>) =>
    rosterAgentKeys({ served: servedKeys, seeded, definitions, definitionsStaged: false });
  const staged = (definitions: Record<string, unknown>) =>
    rosterAgentKeys({ served: [...servedKeys, "checker"], seeded, definitions, definitionsStaged: true });

  it("offers every agent of the roster, the team-lead members included", () => {
    const roster = stored({});
    for (const key of ["lead", "reverser", "triage", "static", "dynamic", "network", "judge"]) {
      expect(roster).toContain(key);
    }
  });

  it("offers an agent staged a moment ago, before it is saved", () => {
    const roster = staged({ strings_checker: custom() });
    expect(roster).toContain("strings_checker");
    expect(new Set(roster).size).toBe(roster.length);
  });

  it("leaves out a stored agent whose removal is staged, and keeps every seed", () => {
    const roster = staged({ static: custom() });
    expect(roster).not.toContain("checker");
    for (const key of seeded) expect(roster).toContain(key);
  });

  it("keeps and marks a stored binding to a key the roster does not hold", () => {
    const roster = stored({});
    const server = { agents: ["static", "retired_agent"] } as Pick<McpServerEntry, "agents">;
    const rows = choiceRows(roster, server.agents);
    expect(rows.find((r) => r.key === "retired_agent")).toEqual({
      key: "retired_agent",
      known: false,
    });
    expect(rows.find((r) => r.key === "static")?.known).toBe(true);

    // Ticking another agent leaves the unknown key in the saved list.
    const next = toggleChoice(server.agents, "lead", true);
    expect(next).toEqual(["static", "retired_agent", "lead"]);
    // Only unticking it takes it away.
    expect(toggleChoice(next, "retired_agent", false)).toEqual(["static", "lead"]);
  });
});
