import { describe, expect, it } from "vitest";
import { describeChange, formatScalar } from "../describeChange";
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

const serversEntry = entry({ key: "core.mcp.servers", type: "json", editor: "server_map", title: "MCP servers" });
const definitionsEntry = entry({
  key: "core.agents.definitions",
  type: "json",
  editor: "agent_definitions",
  title: "Agent definitions",
});
const profilesEntry = entry({ key: "core.agents.profiles", type: "json", editor: "stages", title: "Profiles" });
const activeProfileEntry = entry({ key: "core.agents.profile", type: "enum", title: "Active profile" });
const llmAgentsEntry = entry({ key: "core.llm.agents", type: "json", title: "Per-agent overrides" });
const mappingEntry = entry({
  key: "core.sandbox.rest.mapping.artifacts",
  path: "sandbox.rest.mapping.artifacts",
  type: "str",
  title: "Artifacts channel mapping",
});

describe("formatScalar", () => {
  it("renders unset for null and undefined", () => {
    expect(formatScalar(null)).toBe("unset");
    expect(formatScalar(undefined)).toBe("unset");
  });

  it("renders non-string scalars via String()", () => {
    expect(formatScalar(8192)).toBe("8192");
    expect(formatScalar(false)).toBe("false");
  });

  it("truncates strings over 60 chars with an ellipsis", () => {
    const long = "x".repeat(80);
    const result = formatScalar(long);
    expect(result).toBe(`${"x".repeat(60)}…`);
    expect(result.length).toBe(61);
  });

  it("renders strings without quotes", () => {
    expect(formatScalar("hello")).toBe("hello");
  });
});

describe("describeChange: scalar/enum", () => {
  it("renders a plain before/after arrow", () => {
    const e = entry({ type: "int", title: "Max tokens" });
    const line = describeChange(e, 4096, 8192);
    expect(line.summary).toBe("4096 → 8192");
    expect(line.key).toBe(e.key);
    expect(line.title).toBe(e.title);
    expect(line.applies).toBe(e.applies);
  });

  it("renders unset for a null before value", () => {
    const e = entry({ type: "str" });
    const line = describeChange(e, null, "gpt-4");
    expect(line.summary).toBe("unset → gpt-4");
  });

  it("truncates a long string scalar", () => {
    const e = entry({ type: "str" });
    const before = "a".repeat(70);
    const line = describeChange(e, before, "short");
    expect(line.summary).toBe(`${"a".repeat(60)}… → short`);
  });
});

describe("describeChange: bool", () => {
  it("renders on/off", () => {
    const e = entry({ type: "bool" });
    expect(describeChange(e, true, false).summary).toBe("on → off");
    expect(describeChange(e, false, true).summary).toBe("off → on");
  });

  it("renders unset for a missing bool", () => {
    const e = entry({ type: "bool" });
    expect(describeChange(e, undefined, true).summary).toBe("unset → on");
  });
});

describe("describeChange: secret", () => {
  it("summarises a new secret value without revealing it", () => {
    const e = entry({ type: "secret", secret: true });
    const line = describeChange(e, "", "sk-super-secret");
    expect(line.summary).toBe("new value");
    expect(JSON.stringify(line)).not.toContain("sk-super-secret");
  });

  it("summarises a cleared secret", () => {
    const e = entry({ type: "secret", secret: true });
    const line = describeChange(e, "**********", null);
    expect(line.summary).toBe("cleared");
  });
});

describe("describeChange: list", () => {
  it("summarises additions and removals with a +/- count and detail", () => {
    const e = entry({ type: "list" });
    const line = describeChange(e, ["a", "b"], ["b", "c", "d"]);
    expect(line.summary).toBe("+2 −1 entries");
    expect(line.detail).toEqual(["+ c", "+ d", "− a"]);
  });
});

describe("describeChange: dict", () => {
  it("summarises added/removed/changed keys with ~ for value changes", () => {
    const e = entry({ type: "dict" });
    const before = { alpha: 1, beta: 2, gamma: 3 };
    const after = { alpha: 1, beta: 20, delta: 4 };
    const line = describeChange(e, before, after);
    expect(line.summary).toBe("+1 −1 entries");
    expect(line.detail).toEqual(["~ beta: 2 → 20", "− gamma: 3", "+ delta: 4"]);
  });
});

describe("describeChange: core.mcp.servers", () => {
  it("summarises a server map", () => {
    const before = {
      network: { enabled: true, transport: "stdio", tools: null },
      old: { enabled: true, transport: "stdio" },
    };
    const after = {
      network: { enabled: false, transport: "stdio", tools: null },
      r2: { enabled: true, transport: "stdio", tools: ["a", "b"] },
    };
    const line = describeChange(serversEntry, before, after);
    expect(line.detail).toEqual(["network: disabled", "old: removed", "r2: added"]);
    expect(line.summary).toBe("3 server(s) changed");
  });

  it("never prints a token", () => {
    const line = describeChange(serversEntry, { s: { auth_token: "old" } }, { s: { auth_token: "new" } });
    expect(JSON.stringify(line)).not.toContain("new");
    expect(line.detail).toEqual(["s: changed: token replaced"]);
  });

  it("reports tools counts including all for null", () => {
    const before = { srv: { enabled: true, transport: "stdio", tools: null } };
    const after = { srv: { enabled: true, transport: "stdio", tools: ["a", "b", "c"] } };
    const line = describeChange(serversEntry, before, after);
    expect(line.detail).toEqual(["srv: changed: tools (all → 3)"]);
  });

  it("reports a token cleared and a token set", () => {
    const cleared = describeChange(serversEntry, { s: { auth_token: "old" } }, { s: { auth_token: "" } });
    expect(cleared.detail).toEqual(["s: changed: token cleared"]);
    const set = describeChange(serversEntry, { s: { auth_token: "" } }, { s: { auth_token: "new" } });
    expect(set.detail).toEqual(["s: changed: token set"]);
  });

  it("lists multiple changed fields together", () => {
    const before = { srv: { enabled: true, transport: "stdio", command: "old-cmd", label: "Srv" } };
    const after = { srv: { enabled: true, transport: "stdio", command: "new-cmd", label: "New label" } };
    const line = describeChange(serversEntry, before, after);
    expect(line.detail).toEqual(["srv: changed: command, label"]);
  });

  /* A flip that travelled with another edit used to disappear —
   * "srv: changed: url" said nothing about the server having been switched
   * off at the same time. */
  it("keeps a disabled flip that happens alongside another field", () => {
    const before = { srv: { enabled: true, transport: "http", url: "http://old" } };
    const after = { srv: { enabled: false, transport: "http", url: "http://new" } };
    const line = describeChange(serversEntry, before, after);
    expect(line.detail).toEqual(["srv: changed: disabled, url"]);
  });

  it("keeps an enabled flip that happens alongside another field", () => {
    const before = { srv: { enabled: false, transport: "http", url: "http://old" } };
    const after = { srv: { enabled: true, transport: "http", url: "http://new" } };
    const line = describeChange(serversEntry, before, after);
    expect(line.detail).toEqual(["srv: changed: enabled, url"]);
  });

  it("still reports a lone enable as one word", () => {
    const before = { srv: { enabled: false, transport: "http", url: "http://x" } };
    const after = { srv: { enabled: true, transport: "http", url: "http://x" } };
    expect(describeChange(serversEntry, before, after).detail).toEqual(["srv: enabled"]);
  });

  /* A VirusTotal registration writes the server map for the operator: the
   * server goes on and a token appears. The review list has to say both, so
   * that what a button did reads the same as what a hand-typed token would. */
  it("says both halves of what a VirusTotal registration changed", () => {
    const before = {
      virustotal: { enabled: false, transport: "streamable-http", url: "https://ai.virustotal.com/mcp", auth_token: "" },
    };
    const after = {
      virustotal: { enabled: true, transport: "streamable-http", url: "https://ai.virustotal.com/mcp", auth_token: "**********" },
    };
    const line = describeChange(serversEntry, before, after);
    expect(line.detail).toEqual(["virustotal: changed: enabled, token set"]);
  });
});

describe("describeChange: core.agents.definitions", () => {
  it("marks a cloned definition with its source", () => {
    const before = {
      network: { role: "network", label: "Network", prompt: "p", tools: [], static_provider: null, enabled: true },
    };
    const after = {
      network: { role: "network", label: "Network", prompt: "p", tools: [], static_provider: null, enabled: true },
      "network-2": {
        role: "network",
        label: "Network (copy)",
        prompt: "p",
        tools: [],
        static_provider: null,
        enabled: true,
      },
    };
    const line = describeChange(definitionsEntry, before, after);
    expect(line.detail).toEqual(["network-2: added (clone of network)"]);
    expect(line.summary).toBe("1 agent(s) changed");
  });

  it("adds a definition plainly when it is not a clone", () => {
    const before = {};
    const after = {
      fresh: { role: "generic", label: "Fresh", prompt: "p", tools: [], static_provider: null, enabled: true },
    };
    const line = describeChange(definitionsEntry, before, after);
    expect(line.detail).toEqual(["fresh: added"]);
  });

  it("reports removed and enabled/disabled toggles", () => {
    const before = {
      gone: { role: "generic", label: "Gone", prompt: "p", tools: [], static_provider: null, enabled: true },
      judge: { role: "judge", label: "Judge", prompt: "p", tools: [], static_provider: null, enabled: true },
    };
    const after = {
      judge: { role: "judge", label: "Judge", prompt: "p", tools: [], static_provider: null, enabled: false },
    };
    const line = describeChange(definitionsEntry, before, after);
    expect(line.detail).toEqual(["gone: removed", "judge: disabled"]);
  });

  it("lists changed fields by their display names", () => {
    const before = {
      a: { role: "generic", label: "A", prompt: "old", tools: [], static_provider: "openai", enabled: true },
    };
    const after = {
      a: { role: "static", label: "A2", prompt: "new", tools: [{ kind: "provider", server: null, name: null }], static_provider: "anthropic", enabled: true },
    };
    const line = describeChange(definitionsEntry, before, after);
    expect(line.detail).toEqual(["a: changed: prompt, tools, static provider, label, role"]);
  });

  it("keeps a disabled flip that happens alongside a prompt edit", () => {
    const before = {
      a: { role: "generic", label: "A", prompt: "old", tools: [], static_provider: null, enabled: true },
    };
    const after = {
      a: { role: "generic", label: "A", prompt: "new", tools: [], static_provider: null, enabled: false },
    };
    expect(describeChange(definitionsEntry, before, after).detail).toEqual([
      "a: changed: disabled, prompt",
    ]);
  });

  it("keeps an enabled flip that happens alongside a prompt edit", () => {
    const before = {
      a: { role: "generic", label: "A", prompt: "old", tools: [], static_provider: null, enabled: false },
    };
    const after = {
      a: { role: "generic", label: "A", prompt: "new", tools: [], static_provider: null, enabled: true },
    };
    expect(describeChange(definitionsEntry, before, after).detail).toEqual([
      "a: changed: enabled, prompt",
    ]);
  });
});

describe("describeChange: core.agents.profiles", () => {
  const stage = (over: Record<string, unknown>) => ({
    key: "analysis",
    label: "",
    kind: "analysis",
    agents: [] as string[],
    depends_on: [] as string[],
    when: "",
    mode: "sequential",
    inject_upstream: "none",
    debate: null,
    builtin_tools: true,
    ...over,
  });
  const team = (label: string, ...stages: unknown[]) => ({ label, stages, analysts: [] });

  it("reports an added team", () => {
    const line = describeChange(profilesEntry, {}, { p1: team("P1", stage({})) });
    expect(line.detail).toEqual(["p1: added"]);
    expect(line.summary).toBe("1 team(s) changed");
  });

  it("reports a removed team", () => {
    const line = describeChange(profilesEntry, { p1: team("P1", stage({})) }, {});
    expect(line.detail).toEqual(["p1: removed"]);
  });

  it("reports an added stage with what it is", () => {
    const before = { p1: team("P1", stage({ agents: ["a"] })) };
    const after = {
      p1: team(
        "P1",
        stage({ agents: ["a"] }),
        stage({ key: "deep", agents: ["b"], depends_on: ["analysis"], when: "has_pcap" })
      ),
    };
    expect(describeChange(profilesEntry, before, after).detail).toEqual([
      "p1/deep: added (analysis, b, after analysis, when has_pcap)",
    ]);
  });

  it("reports a removed stage", () => {
    const before = { p1: team("P1", stage({ agents: ["a"] }), stage({ key: "deep" })) };
    const after = { p1: team("P1", stage({ agents: ["a"] })) };
    expect(describeChange(profilesEntry, before, after).detail).toEqual(["p1/deep: removed"]);
  });

  it("reports a reordered stage list once, not field by field", () => {
    const first = stage({ key: "triage", agents: ["a"] });
    const second = stage({ key: "deep", agents: ["b"] });
    const before = { p1: team("P1", first, second) };
    const after = { p1: team("P1", second, first) };
    expect(describeChange(profilesEntry, before, after).detail).toEqual([
      "p1: stages reordered (deep → triage)",
    ]);
  });

  it("reports an agent set change with +/- counts", () => {
    const before = { p1: team("P1", stage({ agents: ["a", "b"] })) };
    const after = { p1: team("P1", stage({ agents: ["a", "c", "d"] })) };
    expect(describeChange(profilesEntry, before, after).detail).toEqual([
      "p1/analysis: agents changed (+2 −1)",
    ]);
  });

  it("reports an agent reorder inside one stage", () => {
    const before = { p1: team("P1", stage({ agents: ["a", "b"] })) };
    const after = { p1: team("P1", stage({ agents: ["b", "a"] })) };
    expect(describeChange(profilesEntry, before, after).detail).toEqual([
      "p1/analysis: agents reordered (b, a)",
    ]);
  });

  it("reports a condition change in both directions", () => {
    const before = { p1: team("P1", stage({ agents: ["a"], when: "" })) };
    const after = { p1: team("P1", stage({ agents: ["a"], when: 'platform == "windows"' })) };
    expect(describeChange(profilesEntry, before, after).detail).toEqual([
      'p1/analysis: condition always → platform == "windows"',
    ]);
    expect(describeChange(profilesEntry, after, before).detail).toEqual([
      'p1/analysis: condition platform == "windows" → always',
    ]);
  });

  it("reports a dependency change, a mode change and an upstream change", () => {
    const before = {
      p1: team("P1", stage({ agents: ["a"] }), stage({ key: "deep", agents: ["b"] })),
    };
    const after = {
      p1: team(
        "P1",
        stage({ agents: ["a"], mode: "parallel" }),
        stage({
          key: "deep",
          agents: ["b"],
          depends_on: ["analysis"],
          inject_upstream: "full",
        })
      ),
    };
    expect(describeChange(profilesEntry, before, after).detail).toEqual([
      "p1/analysis: runs parallel",
      "p1/deep: depends on analysis",
      "p1/deep: upstream findings full",
    ]);
  });

  it("reports the debate options and the built-in tool switch", () => {
    const before = { p1: team("P1", stage({ agents: ["a"] })) };
    const after = {
      p1: team(
        "P1",
        stage({
          agents: ["a"],
          builtin_tools: false,
          debate: { max_rounds: 2, consensus_threshold: 0.9, sycophancy_check: true },
        })
      ),
    };
    expect(describeChange(profilesEntry, before, after).detail).toEqual([
      "p1/analysis: built-in tools off",
      "p1/analysis: debate 2 round(s), threshold 0.9",
    ]);
  });

  it("reports a team rename alongside a stage edit", () => {
    const before = { p1: team("P1", stage({ agents: ["a", "b"] })) };
    const after = { p1: team("Renamed", stage({ agents: ["a", "c"] })) };
    const line = describeChange(profilesEntry, before, after);
    expect(line.detail).toEqual(["p1/analysis: agents changed (+1 −1)", "p1: label changed"]);
    expect(line.summary).toBe("1 team(s) changed");
  });
});

describe("describeChange: core.agents.profile", () => {
  it("names the active profile switch", () => {
    const line = describeChange(activeProfileEntry, "default", "thorough");
    expect(line.summary).toBe("active profile: default → thorough");
  });
});

describe("describeChange: core.llm.agents", () => {
  it("summarises a per-agent override", () => {
    const before = {};
    const after = { network: { provider: "anthropic", model: "claude", temperature: 0.2 } };
    const line = describeChange(llmAgentsEntry, before, after);
    expect(line.detail).toEqual(["network: anthropic/claude (temp 0.2)"]);
    expect(line.summary).toBe("1 override(s) changed");
  });

  it("omits the temp suffix when temperature is unset", () => {
    const before = {};
    const after = { network: { provider: "openai", model: "gpt-4" } };
    const line = describeChange(llmAgentsEntry, before, after);
    expect(line.detail).toEqual(["network: openai/gpt-4"]);
  });

  it("names a per-agent endpoint", () => {
    const before = {};
    const after = {
      network: { provider: "openai", model: "qwen", base_url: "http://127.0.0.1:8081/v1" },
    };
    const line = describeChange(llmAgentsEntry, before, after);
    expect(line.detail).toEqual(["network: openai/qwen @ http://127.0.0.1:8081/v1"]);
  });

  it("keeps the temp suffix last when both are set", () => {
    const before = {};
    const after = {
      network: {
        provider: "ollama",
        model: "qwen3:8b",
        base_url: "http://gpu-box:11434",
        temperature: 0.2,
      },
    };
    const line = describeChange(llmAgentsEntry, before, after);
    expect(line.detail).toEqual(["network: ollama/qwen3:8b @ http://gpu-box:11434 (temp 0.2)"]);
  });

  it("reports a removed override", () => {
    const before = { network: { provider: "openai", model: "gpt-4" } };
    const after = {};
    const line = describeChange(llmAgentsEntry, before, after);
    expect(line.detail).toEqual(["network: override removed"]);
  });
});

describe("describeChange: core.sandbox.rest.mapping.*", () => {
  it("names the channel from the last path segment", () => {
    const line = describeChange(mappingEntry, "$.old", "$.new");
    expect(line.summary).toBe("channel artifacts: $.old → $.new");
  });
});
