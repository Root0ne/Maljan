import { describe, expect, it } from "vitest";
import {
  BUILTIN_AGENT_KEYS,
  comparableSaved,
  displayedDefinitions,
  stagedDefinitions,
} from "../agentStaging";
import { cloneDefinition } from "../AgentDefinitionsEditor";
import type { AgentDefinitionEntry } from "@/types/settings";

/** A built-in as the store holds it after a seed gained a tool the row predates. */
function staleBuiltin(role: AgentDefinitionEntry["role"], label: string): AgentDefinitionEntry {
  return { role, label, prompt: null, tools: [], static_provider: null, enabled: true };
}

const saved: Record<string, AgentDefinitionEntry> = {
  static: {
    role: "static",
    label: "Static analyst",
    prompt: null,
    tools: [{ kind: "mcp", server: "analysis", name: null }],
    static_provider: null,
    enabled: true,
  },
  dynamic: staleBuiltin("dynamic", "Dynamic analyst"),
  network: staleBuiltin("network", "Network analyst"),
  judge: staleBuiltin("judge", "Judge"),
  reporter: staleBuiltin("report", "Reporter"),
};

const ahmet: AgentDefinitionEntry = {
  role: "generic",
  label: "Ahmet",
  prompt: "Temporary audit agent.",
  tools: [],
  static_provider: null,
  enabled: true,
};

describe("what an agent-map edit sends", () => {
  it("sends a built-in nobody touched as its lever alone", () => {
    const sent = stagedDefinitions({ ...saved, ahmet }, saved);
    expect(sent.static).toEqual({ role: "static", enabled: true });
    expect(sent.judge).toEqual({ role: "judge", enabled: true });
    expect(sent.ahmet).toEqual(ahmet);
  });

  it("keeps a built-in's one editable field", () => {
    const next = {
      ...saved,
      static: { ...saved.static, enabled: false },
      ahmet,
    };
    expect(stagedDefinitions(next, saved).static).toEqual({ role: "static", enabled: false });
  });

  it("sends the map back unchanged when the edit was undone", () => {
    // The apply bar unstages a value that deep-equals what is stored, so a
    // narrowed map here would leave "1 change" on screen after a full revert.
    expect(stagedDefinitions({ ...saved }, saved)).toEqual(saved);
  });

  it("sends nothing for a custom agent that was removed", () => {
    const withAhmet = { ...saved, ahmet };
    const sent = stagedDefinitions(saved, withAhmet);
    expect("ahmet" in sent).toBe(false);
  });
});

describe("what the agent list draws", () => {
  it("draws the stored built-in behind the narrowed one it sends", () => {
    const sent = stagedDefinitions({ ...saved, ahmet }, saved);
    const shown = displayedDefinitions(sent, saved);
    expect(shown.static).toEqual(saved.static);
    expect(Object.keys(shown)).toEqual([...Object.keys(saved), "ahmet"]);
  });

  it("draws the staged lever rather than the stored one", () => {
    const next = { ...saved, static: { ...saved.static, enabled: false } };
    const shown = displayedDefinitions(stagedDefinitions(next, saved), saved);
    expect(shown.static.enabled).toBe(false);
    expect(shown.static.label).toBe("Static analyst");
  });

  it("draws what is stored while nothing is staged", () => {
    expect(displayedDefinitions(null, saved)).toEqual(saved);
  });

  it("stops drawing a custom agent that was removed", () => {
    const withAhmet = { ...saved, ahmet };
    const shown = displayedDefinitions(stagedDefinitions(saved, withAhmet), withAhmet);
    expect("ahmet" in shown).toBe(false);
  });
});


/* The setup guide edits the same leaf as the console, through the same
 * provider, so it reads and writes the same narrowed value. Cloning a built-in
 * from that value used to read `tools` off an entry that carries none. */
describe("cloning a built-in from what the guide holds", () => {
  const stagedAfterAnEdit = stagedDefinitions(
    { ...saved, ahmet },
    saved,
  );

  it("names every built-in, so the guide's chooser offers them all", () => {
    for (const key of BUILTIN_AGENT_KEYS) {
      expect(key in saved).toBe(true);
    }
  });

  for (const source of ["static", "dynamic", "network", "judge", "reporter"]) {
    it(`clones ${source} from the map the guide draws`, () => {
      const drawn = displayedDefinitions(stagedAfterAnEdit, saved);
      const cloned = cloneDefinition(drawn, `${source}_copy`, source);

      expect(cloned[`${source}_copy`].role).toBe(saved[source].role);
      expect(cloned[`${source}_copy`].tools).toEqual(saved[source].tools);
      expect(cloned[`${source}_copy`].label).toBe(`${saved[source].label} (copy)`);
      // And the clone goes back out in the shape the save sends.
      const sent = stagedDefinitions(cloned, saved);
      expect(sent[source]).toEqual({ role: saved[source].role, enabled: true });
      expect(sent[`${source}_copy`]).toEqual(cloned[`${source}_copy`]);
    });
  }

  it("gives a tool-less clone rather than throwing on a narrowed source", () => {
    const narrowed = stagedAfterAnEdit as Record<string, AgentDefinitionEntry>;
    expect(() => cloneDefinition(narrowed, "judge_copy", "judge")).not.toThrow();
    expect(cloneDefinition(narrowed, "judge_copy", "judge").judge_copy.tools).toEqual([]);
  });
});

describe("what the review panel compares against", () => {
  it("narrows the stored map for the leaf that is staged narrowed", () => {
    const narrowed = comparableSaved("core.agents.definitions", saved) as Record<
      string,
      unknown
    >;
    expect(narrowed.static).toEqual({ role: "static", enabled: true });
  });

  it("leaves every other leaf as it stands", () => {
    expect(comparableSaved("core.llm.provider", "openai")).toBe("openai");
    expect(comparableSaved("core.agents.definitions", null)).toBeNull();
  });
});
