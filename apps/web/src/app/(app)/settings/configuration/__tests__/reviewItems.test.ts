import { describe, expect, it } from "vitest";
import { buildReviewItems } from "../ReviewList";
import type { ReviewSource } from "../ReviewList";
import type { CatalogEntry, SettingsSchema } from "@/types/settings";

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
  secrets_available: true,
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

    expect(byKey.get(maxTokens.key)?.error).toBe("must be a positive integer");
    expect(byKey.get(apiKey.key)?.error).toBeUndefined();
  });

  it("never renders a secret's value, only that a new one was staged", () => {
    const items = buildReviewItems(baseSource());
    const byKey = new Map(items.map((i) => [i.key, i]));

    expect(byKey.get(apiKey.key)?.summary).toBe("new value");
  });
});
