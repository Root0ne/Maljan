import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import schema from "@/test-fixtures/settings-schema.json";
import type { AgentDefinitionEntry, McpServerEntry } from "@/types/settings";
import {
  AgentDetail,
  type AgentResolveApi,
  withTechniqueLine,
} from "../AgentDefinitionsEditor";
import { rosterAgentKeys } from "../choiceRows";
import { EMPTY_SERVER, ServerDetail, type ServerProbeApi } from "../ServerMapEditor";

/** One served catalog entry, picked by its editor (the served-schema fixture). */
function served(editor: string): Record<string, unknown> {
  for (const group of (schema as { groups: { entries: Record<string, unknown>[] }[] }).groups) {
    for (const entry of group.entries) {
      if (entry.editor === editor) return entry;
    }
  }
  throw new Error(`no ${editor} entry in the served schema`);
}

const idle = async () => undefined;

const probe: ServerProbeApi = {
  probes: {},
  result: undefined,
  stale: false,
  probe: idle,
  noteEdit: () => undefined,
};

const resolve: AgentResolveApi = {
  probes: {},
  result: undefined,
  details: null,
  manifests: {},
  manifestErrors: {},
  resolve: idle,
  loadManifest: idle,
  clearProbe: () => undefined,
  noteEdit: () => undefined,
};

/** The `<input>` tag whose aria-label is exactly `label`, or undefined. */
function checkbox(html: string, label: string): string | undefined {
  return html.match(new RegExp(`<input[^>]*aria-label="${label}"[^>]*>`))?.[0];
}

function serverHtml(agents: string[], roster: readonly string[]): string {
  const value: Record<string, McpServerEntry> = { extra: { ...EMPTY_SERVER, agents } };
  return renderToStaticMarkup(
    createElement(ServerDetail, {
      serverKey: "extra",
      value,
      onChange: () => undefined,
      probe,
      sections: ["agents"],
      agentKeys: roster,
    }),
  );
}

describe("the server detail's agent boxes", () => {
  const entry = served("server_map");
  const roster = rosterAgentKeys({
    served: entry.agent_keys as string[],
    seeded: entry.builtin_agent_keys as string[],
    definitions: {},
    definitionsStaged: false,
  });

  it("draws one box per agent of the roster, the team-lead members included", () => {
    const html = serverHtml([], roster);
    for (const key of ["lead", "reverser", "triage", "static", "judge"]) {
      expect(checkbox(html, `extra agent ${key}`), key).toBeDefined();
    }
  });

  it("draws a stored binding the roster does not hold, ticked and marked", () => {
    const html = serverHtml(["static", "retired_agent"], roster);
    expect(checkbox(html, "extra agent retired_agent")).toContain("checked");
    expect(html).toContain("(not a known agent)");
    expect(checkbox(html, "extra agent static")).toContain("checked");
  });

  it("marks an agent whose removal is staged as not known", () => {
    const staged = rosterAgentKeys({
      served: [...roster, "checker"],
      seeded: entry.builtin_agent_keys as string[],
      definitions: { static: {} },
      definitionsStaged: true,
    });
    expect(staged).not.toContain("checker");
    expect(staged).toContain("lead");
    const html = serverHtml(["checker"], staged);
    expect(html).toContain("(not a known agent)");
  });
});

describe("the agent detail's input data and sandbox row", () => {
  const vocabulary = served("agent_definitions").data_source_choices as string[];

  function agentHtml(key: string, definition: AgentDefinitionEntry): string {
    return renderToStaticMarkup(
      createElement(AgentDetail, {
        agentKey: key,
        definitions: { [key]: definition },
        onChange: () => undefined,
        llmAgents: {},
        onChangeLlmAgents: () => undefined,
        llmGlobal: { providerChoices: null, providerValue: null, modelValue: null },
        servers: {},
        staticProviders: [],
        resolve,
        sections: ["identity", "tools"],
        dataSourceChoices: vocabulary,
      }),
    );
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

  it("draws a box per served input slice, ticking the stored ones", () => {
    const html = agentHtml("checker", { ...base, data_sources: ["sandbox.behavior"] });
    for (const source of vocabulary) {
      expect(checkbox(html, `checker input ${source}`), source).toBeDefined();
    }
    expect(checkbox(html, "checker input sandbox.behavior")).toContain("checked");
    expect(checkbox(html, "checker input sample.path")).not.toContain("checked");
  });

  it("offers the sandbox tools on a custom agent and ticks a stored reference", () => {
    const off = agentHtml("checker", base);
    expect(checkbox(off, "checker sandbox tools")).toBeDefined();
    expect(checkbox(off, "checker sandbox tools")).not.toContain("checked");
    const on = agentHtml("checker", {
      ...base,
      tools: [{ kind: "sandbox", server: null, name: null }],
    });
    expect(checkbox(on, "checker sandbox tools")).toContain("checked");
  });

  it("shows the built-in dynamic analyst's sandbox reference ticked and locked", () => {
    const html = agentHtml("dynamic", {
      ...base,
      role: "dynamic",
      tools: [{ kind: "sandbox", server: null, name: null }],
    });
    const box = checkbox(html, "dynamic sandbox tools");
    expect(box).toContain("checked");
    expect(box).toContain("disabled");
  });
});

describe("the agent detail's ATT&CK technique line switch", () => {
  const seeded = served("agent_definitions").builtin_agent_keys as string[];

  function agentHtml(
    key: string,
    definition: AgentDefinitionEntry,
    builtinAgentKeys: readonly string[] = seeded,
  ): string {
    return renderToStaticMarkup(
      createElement(AgentDetail, {
        agentKey: key,
        definitions: { [key]: definition },
        onChange: () => undefined,
        llmAgents: {},
        onChangeLlmAgents: () => undefined,
        llmGlobal: { providerChoices: null, providerValue: null, modelValue: null },
        servers: {},
        staticProviders: [],
        resolve,
        sections: ["identity"],
        builtinAgentKeys,
      }),
    );
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

  it("draws the switch on a custom agent, on when the field is absent", () => {
    const html = agentHtml("checker", base);
    const box = checkbox(html, "checker attck technique line");
    expect(box).toBeDefined();
    expect(box).toContain("checked");
    expect(box).not.toContain("disabled");
    expect(html).toContain("still read and checked");
  });

  it("draws a stored off as unticked", () => {
    const html = agentHtml("checker", { ...base, attck_techniques: false });
    expect(checkbox(html, "checker attck technique line")).not.toContain("checked");
  });

  it("locks the switch on every built-in the API serves, the seeded prompt agents included", () => {
    expect(seeded).toHaveLength(9);
    for (const key of ["lead", "reverser", "triage", "android_static", "static", "judge"]) {
      expect(seeded, key).toContain(key);
    }
    for (const key of seeded) {
      // Drawn on a prompt role, the one that would otherwise offer the switch.
      for (const role of ["generic", "lead"] as const) {
        const box = checkbox(agentHtml(key, { ...base, role }), `${key} attck technique line`);
        expect(box, `${key} as ${role}`).toContain("checked");
        expect(box, `${key} as ${role}`).toContain("disabled");
      }
    }
  });

  it("draws a seeded built-in fully read-only, its enabled switch aside", () => {
    const html = renderToStaticMarkup(
      createElement(AgentDetail, {
        agentKey: "lead",
        definitions: {
          lead: { ...base, role: "lead", tools: [{ kind: "sandbox", server: null, name: null }] },
        },
        onChange: () => undefined,
        llmAgents: {},
        onChangeLlmAgents: () => undefined,
        llmGlobal: { providerChoices: null, providerValue: null, modelValue: null },
        servers: {},
        staticProviders: [],
        resolve,
        sections: ["header", "identity", "prompt", "tools"],
        dataSourceChoices: served("agent_definitions").data_source_choices as string[],
        builtinAgentKeys: seeded,
      }),
    );
    const controls = html.match(/<(input|textarea|select)\b[^>]*>/g) ?? [];
    const editable = controls.filter(
      (tag) => !/\sdisabled[\s=>]/.test(tag) && !tag.includes('aria-label="lead enabled"'),
    );
    expect(controls.length).toBeGreaterThan(8);
    expect(editable).toEqual([]);
    expect(html).toContain("Prompt (built in, read-only)");
    expect(html).not.toContain(">Remove<");
    expect(checkbox(html, "lead enabled")).not.toContain("disabled");
  });

  it("draws the seeded reverser's provider reference ticked and locked", () => {
    const html = renderToStaticMarkup(
      createElement(AgentDetail, {
        agentKey: "reverser",
        definitions: {
          reverser: {
            ...base,
            role: "generic",
            tools: [{ kind: "provider", server: null, name: null }],
          },
        },
        onChange: () => undefined,
        llmAgents: {},
        onChangeLlmAgents: () => undefined,
        llmGlobal: { providerChoices: null, providerValue: null, modelValue: null },
        servers: {},
        staticProviders: [],
        resolve,
        sections: ["tools"],
        builtinAgentKeys: seeded,
      }),
    );
    const box = checkbox(html, "reverser provider tools");
    expect(box).toContain("checked");
    expect(box).toContain("disabled");
  });

  it("locks the enabled switch of the agents the API serves as always enabled", () => {
    const always = served("agent_definitions").always_enabled_agent_keys as string[];
    expect(always.length).toBeGreaterThan(0);
    const header = (key: string, role: AgentDefinitionEntry["role"]) =>
      renderToStaticMarkup(
        createElement(AgentDetail, {
          agentKey: key,
          definitions: { [key]: { ...base, role } },
          onChange: () => undefined,
          llmAgents: {},
          onChangeLlmAgents: () => undefined,
          llmGlobal: { providerChoices: null, providerValue: null, modelValue: null },
          servers: {},
          staticProviders: [],
          resolve,
          sections: ["header"],
          builtinAgentKeys: seeded,
          alwaysEnabledAgentKeys: always,
        }),
      );
    for (const key of always) {
      expect(checkbox(header(key, "judge"), `${key} enabled`), key).toContain("disabled");
    }
    const other = seeded.find((key) => !always.includes(key)) as string;
    expect(checkbox(header(other, "static"), `${other} enabled`)).not.toContain("disabled");
  });

  it("leaves an operator's own lead agent editable", () => {
    const html = renderToStaticMarkup(
      createElement(AgentDetail, {
        agentKey: "planner",
        definitions: { planner: { ...base, role: "lead" } },
        onChange: () => undefined,
        llmAgents: {},
        onChangeLlmAgents: () => undefined,
        llmGlobal: { providerChoices: null, providerValue: null, modelValue: null },
        servers: {},
        staticProviders: [],
        resolve,
        sections: ["header", "identity", "prompt", "tools"],
        builtinAgentKeys: seeded,
      }),
    );
    expect(html).toMatch(/<textarea[^>]*aria-label="planner prompt"(?![^>]*disabled)[^>]*>/);
    expect(html).toContain(">Remove<");
  });

  it("locks the five class built-ins when the API serves no list", () => {
    const box = checkbox(
      agentHtml("static", { ...base, role: "generic" }, []),
      "static attck technique line",
    );
    expect(box).toContain("disabled");
  });

  it("fixes the switch on a clone of a role that keeps its own claim format", () => {
    const html = agentHtml("static_r2", { ...base, role: "static" });
    const box = checkbox(html, "static_r2 attck technique line");
    expect(box).toContain("checked");
    expect(box).toContain("disabled");
    expect(html).toContain("keeps its own claim format");
  });

  it("leaves a stored off on such a role unlocked, so it can be put right", () => {
    const html = agentHtml("static_r2", { ...base, role: "static", attck_techniques: false });
    expect(checkbox(html, "static_r2 attck technique line")).not.toContain("disabled");
  });

  it("offers the switch on an operator's lead agent", () => {
    const html = agentHtml("planner", { ...base, role: "lead" });
    expect(checkbox(html, "planner attck technique line")).not.toContain("disabled");
  });

  it("stores off as false and on as no field, so off then on is the loaded definition", () => {
    const off = withTechniqueLine(base, false);
    expect(off.attck_techniques).toBe(false);
    const back = withTechniqueLine(off, true);
    expect("attck_techniques" in back).toBe(false);
    expect(back).toEqual(base);
    expect(JSON.parse(JSON.stringify(off))).toEqual({ ...base, attck_techniques: false });
  });
});
