import { describe, expect, it } from "vitest";

import schema from "@/test-fixtures/settings-schema.json";
import type { AgentDefinitionEntry, ToolRefEntry } from "@/types/settings";
import { cloneDefinition, displayedDefinitions, stagedDefinitions } from "../agentStaging";
import {
  capabilitiesReaching,
  capabilityRef,
  holdsServer,
  offeredCapabilities,
  sameToolRef,
  withoutServer,
  type CapabilityServers,
} from "../capabilityRefs";

/** What the API serves for the agent definitions today (the served-schema fixture). */
function servedReach(): CapabilityServers {
  for (const group of (schema as { groups: { entries: Record<string, unknown>[] }[] }).groups) {
    for (const entry of group.entries) {
      if (entry.editor === "agent_definitions") {
        return (entry.capability_servers ?? {}) as CapabilityServers;
      }
    }
  }
  throw new Error("no agent definitions entry in the served schema");
}

const mcp = (server: string, name: string | null = null): ToolRefEntry => ({
  kind: "mcp",
  server,
  name,
});
const reputation = capabilityRef("reputation");

/** The seeded static analyst's tools as the API stores them. */
const STATIC_TOOLS: ToolRefEntry[] = [mcp("analysis"), mcp("knowledge"), reputation];

function definition(tools: ToolRefEntry[]): AgentDefinitionEntry {
  return {
    role: "static",
    label: "Static analyst",
    prompt: null,
    tools,
    static_provider: null,
    enabled: true,
    max_steps: null,
    timeout_seconds: null,
  };
}

describe("the served capability reach", () => {
  it("is the server the built-ins named by key before", () => {
    expect(servedReach()).toEqual({ reputation: ["virustotal"] });
  });
});

describe("a built-in agent's tool boxes", () => {
  const reach = servedReach();

  it("tick the server its capability reaches, as the box was ticked by key before", () => {
    expect(holdsServer(STATIC_TOOLS, "virustotal", reach)).toBe(true);
    expect(capabilitiesReaching(STATIC_TOOLS, "virustotal", reach)).toEqual(["reputation"]);
    expect(holdsServer(STATIC_TOOLS, "analysis", reach)).toBe(true);
    expect(holdsServer(STATIC_TOOLS, "threatintel", reach)).toBe(false);
  });

  it("draw one capability row, ticked", () => {
    expect(offeredCapabilities(STATIC_TOOLS, reach)).toEqual(["reputation"]);
    expect(STATIC_TOOLS.some((t) => sameToolRef(t, reputation))).toBe(true);
  });

  it("still draw a capability row for a reference the API serves no reach for", () => {
    expect(offeredCapabilities([capabilityRef("other_kind")], reach)).toEqual([
      "reputation",
      "other_kind",
    ]);
  });
});

describe("a clone", () => {
  const reach = servedReach();
  const saved = { static: definition(STATIC_TOOLS) };

  it("copies the capability reference and stages it, never dropping it", () => {
    const cloned = cloneDefinition(displayedDefinitions(null, saved), "mine", "static");
    expect(cloned.mine.tools).toEqual(STATIC_TOOLS);
    const staged = stagedDefinitions(cloned, saved);
    expect(staged.mine).toEqual(cloned.mine);
    expect((staged.mine as AgentDefinitionEntry).tools).toContainEqual(reputation);
  });

  it("drops the capability when its server's box is unticked, as unticking the server did", () => {
    expect(withoutServer(STATIC_TOOLS, "virustotal", reach)).toEqual([
      mcp("analysis"),
      mcp("knowledge"),
    ]);
  });

  it("drops a server named by key and keeps the capability that reaches others", () => {
    const tools = [mcp("virustotal"), mcp("knowledge"), reputation];
    expect(withoutServer(tools, "knowledge", reach)).toEqual([mcp("virustotal"), reputation]);
    expect(withoutServer(tools, "virustotal", reach)).toEqual([mcp("knowledge")]);
  });

  it("keeps a single tool of the server when the whole box is unticked", () => {
    const tools = [mcp("virustotal", "get_file_report"), reputation];
    expect(withoutServer(tools, "virustotal", reach)).toEqual([
      mcp("virustotal", "get_file_report"),
    ]);
  });

  it("tells a capability reference from every other kind", () => {
    expect(sameToolRef(reputation, capabilityRef("reputation"))).toBe(true);
    expect(sameToolRef(reputation, capabilityRef("other_kind"))).toBe(false);
    expect(sameToolRef(reputation, mcp("virustotal"))).toBe(false);
  });
});
