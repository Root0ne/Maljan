import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import schema from "@/test-fixtures/settings-schema.json";
import type { AgentDefinitionEntry, McpServerEntry } from "@/types/settings";
import { AgentDetail, type AgentResolveApi } from "../AgentDefinitionsEditor";
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
