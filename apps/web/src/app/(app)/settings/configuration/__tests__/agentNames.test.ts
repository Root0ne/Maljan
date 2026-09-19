import { describe, expect, it } from "vitest";

import type { AgentDefinitionEntry } from "@/types/settings";
import { agentDisplayName, agentFullName, agentKeySuffix } from "../agentNames";

function agent(over: Partial<AgentDefinitionEntry> = {}): AgentDefinitionEntry {
  return {
    role: "generic",
    label: "",
    prompt: null,
    tools: [],
    static_provider: null,
    enabled: true,
    max_steps: null,
    timeout_seconds: null,
    ...over,
  };
}

/* A team of ahmet, mehmet and cemal, where the second ahmet got the slug
 * `ahmet_1` because the first one had already taken the name. */
const DEFINITIONS: Record<string, AgentDefinitionEntry> = {
  ahmet: agent({ label: "ahmet" }),
  ahmet_1: agent({ label: "mehmet" }),
  cemal: agent({ label: "" }),
  judge: agent({ role: "judge", label: "Judge" }),
};

describe("what an agent is called", () => {
  it("uses the name the operator gave it", () => {
    expect(agentDisplayName("ahmet_1", DEFINITIONS)).toBe("mehmet");
    expect(agentDisplayName("judge", DEFINITIONS)).toBe("Judge");
  });

  it("falls back to the key when no name was given", () => {
    expect(agentDisplayName("cemal", DEFINITIONS)).toBe("cemal");
    expect(agentDisplayName("nobody", DEFINITIONS)).toBe("nobody");
    expect(agentDisplayName("cemal", null)).toBe("cemal");
  });

  it("shows the key only where it says something the name does not", () => {
    expect(agentKeySuffix("ahmet_1", DEFINITIONS)).toBe("ahmet_1");
    expect(agentKeySuffix("ahmet", DEFINITIONS)).toBe("");
    expect(agentKeySuffix("cemal", DEFINITIONS)).toBe("");
  });

  it("names an agent once where there is room for one string", () => {
    expect(agentFullName("ahmet_1", DEFINITIONS)).toBe("mehmet (ahmet_1)");
    expect(agentFullName("ahmet", DEFINITIONS)).toBe("ahmet");
    expect(agentFullName("cemal", DEFINITIONS)).toBe("cemal");
  });
});
