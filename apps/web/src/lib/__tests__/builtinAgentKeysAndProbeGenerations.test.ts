import { describe, expect, it } from "vitest";
import {
  builtinAgentKeys,
  builtinAgentKeysOf,
  displayedDefinitions,
  narrowBuiltins,
} from "@/app/(app)/settings/configuration/agentStaging";
import { ProbeGenerations } from "@/app/(app)/settings/configuration/probeGenerations";
import { pollStoppedText } from "@/app/(app)/settings/configuration/attckData";
import { graphViewHint, GRAPH_FIRST_LIMIT } from "@/components/analysis/stixGraph";
import type { AgentDefinitionEntry } from "@/types/settings";

const def = (role: string) => ({ role, enabled: true, label: "l", prompt: "p" }) as unknown as AgentDefinitionEntry;

describe("built-in agent keys come from the served list (WA-L7)", () => {
  it("uses the served list, so a built-in the API adds is locked", () => {
    const keys = builtinAgentKeys(["static", "triager"]);
    expect(keys.has("triager")).toBe(true);
    expect(keys.has("judge")).toBe(false);
  });
  it("falls back to the five only when the API served none", () => {
    expect(builtinAgentKeys(undefined).has("judge")).toBe(true);
    expect(builtinAgentKeys([]).has("reporter")).toBe(true);
  });
  it("reads the list off the schema entry", () => {
    const schema = {
      groups: [{ entries: [{ key: "core.agents.definitions", builtin_agent_keys: ["a", "b"] }] }],
    };
    expect([...builtinAgentKeysOf(schema)]).toEqual(["a", "b"]);
  });
  it("narrowing and drawing follow the list they are given", () => {
    const map = { a: def("static"), custom: def("generic") };
    const narrowed = narrowBuiltins(map, builtinAgentKeys(["a"]));
    expect(Object.keys(narrowed.a)).toEqual(["role", "enabled"]);
    expect(narrowed.custom).toBe(map.custom);
    expect(displayedDefinitions({ a: { role: "static", enabled: false } }, map, builtinAgentKeys(["a"])).a).toMatchObject({
      enabled: false,
      label: "l",
    });
  });
});

describe("a probe that lands after an edit is discarded (WA-L5)", () => {
  it("keeps an answer only under the generation it was asked in", () => {
    const gens = new ProbeGenerations();
    const taken = gens.take("agent");
    expect(gens.isCurrent("agent", taken)).toBe(true);
    gens.bump("agent");
    expect(gens.isCurrent("agent", taken)).toBe(false);
    expect(gens.isCurrent("other", gens.take("other"))).toBe(true);
  });
});

describe("ATT&CK poll stop text (WA-L16)", () => {
  it("says why tracking stopped and that the update may still run", () => {
    const text = pollStoppedText("Forbidden");
    expect(text).toContain("Forbidden");
    expect(text).toMatch(/may still be running/);
  });
});

describe("Graph option hint (WB-L10)", () => {
  it("warns only for a bundle past the size the panel opens the graph on", () => {
    expect(graphViewHint(GRAPH_FIRST_LIMIT)).toBeNull();
    expect(graphViewHint(GRAPH_FIRST_LIMIT + 1)).toMatch(/lay out slowly/);
  });
});
