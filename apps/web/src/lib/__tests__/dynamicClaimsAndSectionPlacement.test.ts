import { describe, expect, it } from "vitest";
import { dynamicAnalystClaims } from "@/components/analysis/dynamicClaims";
import { tabOfSection } from "@/components/analysis/reportSections";
import type { AgentFindingDTO } from "@/lib/api";
import type { JobRoster } from "@/types";

function finding(agent_name: string, domain: string): AgentFindingDTO {
  return { agent_name, domain, claims: [{ claim: "c" }] } as unknown as AgentFindingDTO;
}
const roster = {
  agents: [
    { key: "ahmet_1", label: "Ahmet", role: "dynamic", stages: [] },
    { key: "dynamic_notes", label: "Notes", role: "static", stages: [] },
  ],
  stages: [],
} as unknown as JobRoster;

describe("DYNAMIC claims come from what the data declares (WB-L3)", () => {
  it("a name containing 'dynamic' under another domain and role is not dynamic", () => {
    expect(dynamicAnalystClaims([finding("dynamic_notes", "static")], roster)).toEqual([]);
    expect(dynamicAnalystClaims([finding("dynamic_notes", "static")])).toEqual([]);
  });
  it("the declared domain decides, whatever the agent is called", () => {
    expect(dynamicAnalystClaims([finding("ahmet_1", "dynamic")]).map((a) => a.agent)).toEqual(["ahmet_1"]);
  });
  it("so does the role the roster gives the agent", () => {
    expect(dynamicAnalystClaims([finding("ahmet_1", "generic")], roster).map((a) => a.agent)).toEqual(["ahmet_1"]);
  });
});

describe("section placement (WB-L2)", () => {
  it("the placement the API declared wins over the key's suffix", () => {
    expect(tabOfSection("custom_imports", { custom_imports: "network" })).toBe("network");
  });
  it("a key with no declared placement keeps its own rule", () => {
    expect(tabOfSection("pe_imports", {})).toBe("static");
    expect(tabOfSection("pe_imports", null)).toBe("static");
    expect(tabOfSection("strings", { strings: "network" })).toBe("static");
  });
  it("a placement naming a tab that draws nothing falls back to the key", () => {
    expect(tabOfSection("pe_imports", { pe_imports: "nonsense" })).toBe("static");
  });
});
