import { describe, expect, it } from "vitest";
import { buildFieldRowProps } from "../fieldRowProps";
import { AGENT_DEFINITIONS_KEY, stagedDefinitions } from "../agentStaging";
import type { SettingsContextValue } from "../SettingsContext";
import type { AgentDefinitionEntry, CatalogEntry } from "@/types/settings";

/**
 * The Teams editor reads the agent map for one thing: what each agent is
 * called. It reads it through the same context the agents editor stages into,
 * and a staged built-in carries its role and its switch and nothing else — so
 * taking the pending value raw left the stage cards and the analyst picker
 * naming five built-ins by key for as long as an agent-map edit was
 * unapplied, which is the walk an operator makes straight after adding one.
 */

function definition(
  role: AgentDefinitionEntry["role"],
  label: string,
): AgentDefinitionEntry {
  return { role, label, prompt: null, tools: [], static_provider: null, enabled: true, max_steps: null, timeout_seconds: null };
}

const stored: Record<string, AgentDefinitionEntry> = {
  static: definition("static", "Static analyst"),
  dynamic: definition("dynamic", "Dynamic analyst"),
  network: definition("network", "Network analyst"),
  judge: definition("judge", "Judge"),
  reporter: definition("report", "Reporter"),
};

const profiles: CatalogEntry = {
  key: "core.agents.profiles",
  namespace: "core",
  path: "agents.profiles",
  type: "json",
  default: null,
  nullable: true,
  choices: null,
  minimum: null,
  maximum: null,
  secret: false,
  group: "agents",
  title: "Team definitions",
  description: "",
  applies: "next_job",
  editable: true,
  reason: null,
  probe: null,
  applies_when: null,
  order: 0,
  choices_from: null,
  editor: "stages",
  subgroup: null,
  advanced: false,
  required_env: null,
};

/** Only what `buildFieldRowProps` actually reads. */
function context(pending: Record<string, unknown>): SettingsContextValue {
  return {
    entriesByKey: { [profiles.key]: profiles },
    values: {
      [AGENT_DEFINITIONS_KEY]: {
        value: stored,
        is_set: true,
        hint: null,
        source: "ui",
        updated_at: null,
        updated_by: null,
      },
    },
    pending,
    errors: {},
    lastResult: null,
    models: [],
    effectiveValue: () => undefined,
    stage: () => undefined,
    unstage: () => undefined,
    reset: async () => undefined,
  } as unknown as SettingsContextValue;
}

describe("the definitions the stages editor is handed", () => {
  it("names every built-in while an agent-map edit is staged", () => {
    const staged = stagedDefinitions(
      {
        ...stored,
        ahmet: {
          role: "generic",
          label: "Ahmet",
          prompt: "Summarise the sample.",
          tools: [],
          static_provider: null,
          enabled: true,
          max_steps: null,
          timeout_seconds: null,
        },
      },
      stored,
    );
    const props = buildFieldRowProps(context({ [AGENT_DEFINITIONS_KEY]: staged }), profiles);

    for (const key of Object.keys(stored)) {
      expect(props.definitions[key].label).toBe(stored[key].label);
    }
    expect(props.definitions.ahmet.label).toBe("Ahmet");
  });

  it("carries a staged edit to a built-in's one lever", () => {
    const staged = stagedDefinitions(
      { ...stored, judge: { ...stored.judge, enabled: false } },
      stored,
    );
    const props = buildFieldRowProps(context({ [AGENT_DEFINITIONS_KEY]: staged }), profiles);

    expect(props.definitions.judge.enabled).toBe(false);
    expect(props.definitions.judge.label).toBe("Judge");
  });

  it("falls back to what is stored when nothing is staged", () => {
    const props = buildFieldRowProps(context({}), profiles);
    expect(props.definitions).toEqual(stored);
  });
});
