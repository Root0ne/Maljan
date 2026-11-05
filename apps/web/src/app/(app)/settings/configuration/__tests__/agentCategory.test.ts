import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import schema from "@/test-fixtures/settings-schema.json";
import type { AgentDefinitionEntry } from "@/types/settings";
import {
  AgentDetail,
  CATEGORY_LABELS,
  CategoryHelp,
  type AgentResolveApi,
} from "../AgentDefinitionsEditor";
import {
  builtinAgentKeys,
  categoryRequired,
  cloneDefinition,
  missingCategoryErrors,
  stagedDefinitions,
} from "../agentStaging";
import { describeChange } from "../describeChange";

/** The owner-approved text under the category select, word for word. */
const HELP =
  "Choose the category that matches what this agent actually does. Malspark sets this " +
  "agent's platform steps by its category: for example, an agent in Reverser is shown the " +
  "functions on the main path it has not read before it gives its final answer. A wrong " +
  "category gives the agent steps that do not fit its work and leaves out steps that would " +
  "help it. If none fits, choose Other; the platform then works out what it can from the " +
  "agent's tools and results.";

function served(editor: string): Record<string, unknown> {
  for (const group of (schema as { groups: { entries: Record<string, unknown>[] }[] }).groups) {
    for (const entry of group.entries) {
      if (entry.editor === editor) return entry;
    }
  }
  throw new Error(`no ${editor} entry in the served schema`);
}

const idle = async () => undefined;
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

const base: AgentDefinitionEntry = {
  role: "generic",
  label: "Mine",
  prompt: "p",
  tools: [],
  static_provider: null,
  enabled: true,
  max_steps: null,
  timeout_seconds: null,
};

function identity(
  key: string,
  definition: AgentDefinitionEntry,
  extra: Record<string, unknown> = {},
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
      categoryChoices: served("agent_definitions").agent_category_choices as string[],
      builtinAgentKeys: served("agent_definitions").builtin_agent_keys as string[],
      ...extra,
    }),
  );
}

function select(html: string, key: string): string {
  const found = html.match(
    new RegExp(`<select[^>]*aria-label="${key} category"[^>]*>[\\s\\S]*?</select>`),
  )?.[0];
  if (!found) throw new Error("no category select");
  return found;
}

describe("the agent category in the editor", () => {
  it("is a required select over the served categories, none chosen on a new agent", () => {
    const fresh = cloneDefinition({}, "mine").mine;
    expect(fresh.category).toBeUndefined();
    const html = select(identity("mine", fresh), "mine");
    expect(html).toContain("required");
    const values = [...html.matchAll(/<option value="([^"]*)"/g)].map((m) => m[1]);
    expect(values).toEqual(["", ...(served("agent_definitions").agent_category_choices as string[])]);
    expect(html).toMatch(/<option value="" disabled="" selected="">Choose a category<\/option>/);
    expect(html).toContain(">Reverser (code reader)<");
  });

  it("serves the six categories the settings model takes, each with a label", () => {
    const choices = served("agent_definitions").agent_category_choices as string[];
    expect(choices).toEqual(["code_reader", "static", "dynamic", "network", "intel", "other"]);
    for (const c of choices) expect(CATEGORY_LABELS[c]).toBeTruthy();
  });

  it("shows a stored category as chosen", () => {
    const html = select(identity("mine", { ...base, category: "intel" }), "mine");
    expect(html).toMatch(/<option value="intel" selected="">Intel \/ reputation<\/option>/);
  });

  it("carries the owner-approved help text word for word, tied to the select", () => {
    const help = renderToStaticMarkup(createElement(CategoryHelp, { id: "x" }));
    expect(help.replace(/<[^>]+>/g, "").replace(/&#x27;/g, "'")).toBe(HELP);
    expect(help).toContain("<em>Reverser</em>");
    expect(help).toContain("<em>Other</em>");
    expect(identity("mine", base)).toContain('aria-describedby="mine-category-help"');
  });

  it("is locked on a built-in", () => {
    const html = select(
      identity("reverser", { ...base, label: "Reverser", category: "code_reader" }),
      "reverser",
    );
    expect(html.match(/<select[^>]*>/)?.[0]).toMatch(/\sdisabled=""/);
  });

  it("draws the API's message under the field", () => {
    const html = identity("mine", base, {
      errors: { "core.agents.definitions.mine.category": "choose the category" },
    });
    expect(html).toContain("choose the category");
  });

  it("keeps the source's category on a clone", () => {
    const cloned = cloneDefinition({ src: { ...base, category: "network" } }, "copy", "src");
    expect(cloned.copy.category).toBe("network");
  });

  it("names a changed category in the review", () => {
    const entry = served("agent_definitions") as never;
    const line = describeChange(
      entry,
      { mine: { ...base, category: "other" } },
      { mine: { ...base, category: "code_reader" } },
    );
    expect(line.detail).toEqual(["mine: changed: category"]);
  });
});

describe("a new agent with no category is refused before a save", () => {
  const choices = served("agent_definitions").agent_category_choices as string[];
  const builtins = builtinAgentKeys(served("agent_definitions").builtin_agent_keys as string[]);
  /** `core.agent_category.CATEGORY_REQUIRED`, as the API words it. */
  const API_TEXT =
    "choose the category that matches what this agent does: code_reader, static, dynamic, " +
    "network, intel, other (other when none fits)";

  it("words it as the API does", () => {
    expect(categoryRequired(choices)).toBe(API_TEXT);
    expect(categoryRequired(null)).toBe(API_TEXT);
  });

  it("names each new agent without one, under its category field", () => {
    const saved = { kept: base };
    const next = {
      ...saved,
      fresh: cloneDefinition(saved, "fresh").fresh,
      chosen: { ...base, category: "static" as const },
    };
    const staged = stagedDefinitions(next, saved, builtins);
    expect(missingCategoryErrors(staged, saved, builtins, choices)).toEqual({
      "core.agents.definitions.fresh.category": API_TEXT,
    });
  });

  it("holds neither a built-in nor a stored agent to it", () => {
    const saved = { kept: base, static: { ...base, role: "static" as const } };
    const next = { ...saved, static: { ...saved.static, enabled: false } };
    const staged = stagedDefinitions(next, saved, builtins);
    expect(missingCategoryErrors(staged, saved, builtins, choices)).toEqual({});
    expect(missingCategoryErrors(undefined, saved, builtins, choices)).toEqual({});
  });

  it("draws the message under the field once the save refused it", () => {
    const fresh = cloneDefinition({}, "fresh").fresh;
    const errors = missingCategoryErrors({ fresh }, {}, builtins, choices);
    expect(identity("fresh", fresh, { errors })).toContain(API_TEXT);
  });
});
