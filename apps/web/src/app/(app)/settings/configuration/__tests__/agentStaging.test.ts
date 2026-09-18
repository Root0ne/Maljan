import { describe, expect, it } from "vitest";
import { displayedDefinitions, stagedDefinitions } from "../agentStaging";
import type { AgentDefinitionEntry } from "@/types/settings";

/** A built-in as the store holds it after a seed gained a tool the row predates. */
function staleBuiltin(role: AgentDefinitionEntry["role"], label: string): AgentDefinitionEntry {
  return { role, label, prompt: null, tools: [], static_provider: null, enabled: true };
}

const saved: Record<string, AgentDefinitionEntry> = {
  static: staleBuiltin("static", "Static analyst"),
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
    expect(Object.keys(shown)).toEqual(["static", "judge", "reporter", "ahmet"]);
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
