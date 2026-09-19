import { describe, expect, it } from "vitest";
import { attentionLine, buildReviewItems, reviewErrors } from "../ReviewList";
import { stagedDefinitions } from "../agentStaging";
import type { ReviewSource } from "../ReviewList";
import type { AgentDefinitionEntry, CatalogEntry, SettingsSchema } from "@/types/settings";

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
    required_env: null,
    ...overrides,
  };
}

const maxTokens = entry({
  key: "core.llm.max_tokens",
  group: "llm",
  title: "Max tokens",
  type: "int",
});
const apiKey = entry({
  key: "core.providers.openai_key",
  group: "providers",
  title: "OpenAI key",
  secret: true,
});
const negotiationTimeout = entry({
  key: "core.negotiation.timeout",
  group: "negotiation",
  title: "Negotiation timeout",
  type: "int",
  applies_when: { "core.llm.provider": ["never-matches"] },
});

const schema: SettingsSchema = {
  groups: [
    {
      key: "llm",
      title: "LLM & model",
      description: "",
      entries: [maxTokens],
    },
    {
      key: "providers",
      title: "Providers",
      description: "",
      entries: [apiKey],
    },
    {
      key: "negotiation",
      title: "Negotiation",
      description: "",
      entries: [negotiationTimeout],
    },
  ],
};

function baseSource(): ReviewSource {
  return {
    schema,
    pending: {
      [maxTokens.key]: 8192,
      [apiKey.key]: "sk-new",
      [negotiationTimeout.key]: 30,
    },
    entriesByKey: {
      [maxTokens.key]: maxTokens,
      [apiKey.key]: apiKey,
      [negotiationTimeout.key]: negotiationTimeout,
    },
    values: {
      [maxTokens.key]: {
        value: 4096,
        is_set: true,
        hint: null,
        source: "ui",
        updated_at: null,
        updated_by: null,
      },
    },
    hiddenKeys: [negotiationTimeout.key],
    errors: {
      [maxTokens.key]: "must be a positive integer",
    },
  };
}

describe("buildReviewItems", () => {
  it("groups by the section and group the key's page lives under", () => {
    const items = buildReviewItems(baseSource());
    const byKey = new Map(items.map((i) => [i.key, i]));

    expect(byKey.get(maxTokens.key)?.sectionTitle).toBe("Models");
    expect(byKey.get(maxTokens.key)?.groupTitle).toBe("LLM & model");
    expect(byKey.get(apiKey.key)?.sectionTitle).toBe("Models");
    expect(byKey.get(apiKey.key)?.groupTitle).toBe("Providers");
    expect(byKey.get(negotiationTimeout.key)?.sectionTitle).toBe("Agents and pipeline");
    expect(byKey.get(negotiationTimeout.key)?.groupTitle).toBe("Negotiation");
  });

  it("marks a hidden key and points its href at the key's own page", () => {
    const items = buildReviewItems(baseSource());
    const byKey = new Map(items.map((i) => [i.key, i]));

    expect(byKey.get(negotiationTimeout.key)?.hidden).toBe(true);
    expect(byKey.get(negotiationTimeout.key)?.href).toBe(
      "/settings/configuration/agents/negotiation"
    );
    expect(byKey.get(maxTokens.key)?.hidden).toBe(false);
    expect(byKey.get(maxTokens.key)?.href).toBe("/settings/configuration/models/llm");
  });

  it("carries the field error through to the matching row only", () => {
    const items = buildReviewItems(baseSource());
    const byKey = new Map(items.map((i) => [i.key, i]));

    expect(byKey.get(maxTokens.key)?.errors).toEqual(["must be a positive integer"]);
    expect(byKey.get(apiKey.key)?.errors).toEqual([]);
  });

  /* One composite leaf can be refused on several of its fields at once. The
   * review panel counted rows and joined the messages with semicolons, so it
   * announced "1 field needs attention" over five sentences read out as one.
   * A row keeps them apart. */
  it("keeps a composite leaf's field errors apart", () => {
    const source = baseSource();
    source.errors = {
      [`${maxTokens.key}.alpha`]: "alpha is wrong",
      [`${maxTokens.key}.beta`]: "beta is wrong",
    };
    const byKey = new Map(buildReviewItems(source).map((i) => [i.key, i]));

    expect(byKey.get(maxTokens.key)?.errors).toEqual(["alpha is wrong", "beta is wrong"]);
  });

  it("never renders a secret's value, only that a new one was staged", () => {
    const items = buildReviewItems(baseSource());
    const byKey = new Map(items.map((i) => [i.key, i]));

    expect(byKey.get(apiKey.key)?.summary).toBe("new value");
  });
});

/* The review panel reads the two halves of an agent-map edit. They are not the
 * same shape — a staged built-in carries its role and its switch and nothing
 * else — so comparing them raw reported every built-in as about to have its
 * prompt, tools and label rewritten. That is the sentence the whole C-C4 fix
 * exists to stop printing, moved out of the error list and into the change
 * list. */
const definitions = entry({
  key: "core.agents.definitions",
  group: "agents",
  title: "Agent definitions",
  type: "json",
  editor: "agent_definitions",
});

function builtin(role: AgentDefinitionEntry["role"], label: string): AgentDefinitionEntry {
  return { role, label, prompt: null, tools: [], static_provider: null, enabled: true };
}

const ahmet: AgentDefinitionEntry = {
  role: "generic",
  label: "Ahmet",
  prompt: "Summarise the sample.",
  tools: [],
  static_provider: null,
  enabled: true,
};

const storedAgents = {
  static: builtin("static", "Static analyst"),
  judge: builtin("judge", "Judge"),
  reporter: builtin("report", "Reporter"),
};

function agentSource(staged: Record<string, unknown>): ReviewSource {
  return {
    schema: {
      groups: [
        { key: "agents", title: "Agents", description: "", entries: [definitions] },
      ],
    },
    pending: { [definitions.key]: staged },
    entriesByKey: { [definitions.key]: definitions },
    values: {
      [definitions.key]: {
        value: storedAgents,
        is_set: true,
        hint: null,
        source: "ui",
        updated_at: null,
        updated_by: null,
      },
    },
    hiddenKeys: [],
    errors: {},
  };
}

describe("an agent-map edit, as the review panel describes it", () => {
  it("announces one added agent and no built-in as changed", () => {
    const staged = stagedDefinitions({ ...storedAgents, ahmet }, storedAgents);
    const [line] = buildReviewItems(agentSource(staged));

    expect(line.summary).toBe("1 agent changed");
    expect(line.detail).toEqual(["ahmet: added"]);
  });

  it("still names a built-in the operator did turn off", () => {
    const staged = stagedDefinitions(
      { ...storedAgents, static: { ...storedAgents.static, enabled: false } },
      storedAgents,
    );
    const [line] = buildReviewItems(agentSource(staged));

    expect(line.summary).toBe("1 agent changed");
    expect(line.detail).toEqual(["static: disabled"]);
  });

  it("still names a custom agent that was removed", () => {
    const withAhmet = { ...storedAgents, ahmet };
    const source = agentSource(stagedDefinitions(storedAgents, withAhmet));
    source.values[definitions.key] = { ...source.values[definitions.key], value: withAhmet };
    const [line] = buildReviewItems(source);

    expect(line.detail).toEqual(["ahmet: removed"]);
  });
});

describe("what the review panel announces", () => {
  it("counts fields across the rows, not rows", () => {
    const source = baseSource();
    source.errors = {
      [`${maxTokens.key}.alpha`]: "alpha is wrong",
      [`${maxTokens.key}.beta`]: "beta is wrong",
      [apiKey.key]: "and this one too",
    };
    const messages = reviewErrors(buildReviewItems(source));

    expect(messages).toEqual(["alpha is wrong", "beta is wrong", "and this one too"]);
    expect(attentionLine(messages.length)).toBe("3 fields need attention");
  });

  it("says it in the singular for one", () => {
    expect(attentionLine(1)).toBe("1 field needs attention");
  });

  it("has nothing to announce when the server refused nothing", () => {
    const source = baseSource();
    source.errors = {};
    expect(reviewErrors(buildReviewItems(source))).toEqual([]);
  });
});
