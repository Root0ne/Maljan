import { describe, expect, it } from "vitest";

import {
  effortField,
  storedChoice,
  withProvider,
} from "@/app/(app)/settings/configuration/modelList";
import type { EffortOptions } from "@/types/settings";

function options(over: Partial<EffortOptions>): EffortOptions {
  return {
    provider: "anthropic",
    model: "claude-haiku-5-5",
    takes_effort: true,
    levels: ["low", "medium", "high"],
    levels_source: "models_api",
    global_key: "core.llm.anthropic.effort",
    global_value: "max",
    ...over,
  };
}

describe("a per-agent effort field", () => {
  it("offers the levels the backend served, blank inheriting the global value", () => {
    const field = effortField(options({}), "");
    expect(field.kind).toBe("select");
    if (field.kind !== "select") return;
    expect(field.choices.map((c) => c.value)).toEqual(["", "low", "medium", "high"]);
    expect(field.choices[0]!.label).toBe("Inherit (max)");
  });

  it("names the provider's default when no global value is set", () => {
    const field = effortField(options({ global_value: null }), "");
    expect(field.kind === "select" && field.choices[0]!.label).toBe(
      "Inherit (the model's default)",
    );
  });

  it("keeps a stored value the backend no longer offers, marked so", () => {
    const field = effortField(options({}), "max");
    expect(field.kind).toBe("select");
    if (field.kind !== "select") return;
    expect(field.choices.at(-1)).toEqual({ value: "max", label: "max (not offered for this model)" });
  });

  it("is typed as written where the endpoint names its own levels", () => {
    const field = effortField(
      options({ provider: "openai", levels: null, global_value: "max" }),
      "",
    );
    expect(field).toEqual({ kind: "text", placeholder: "inherit (max)" });
  });

  it("is not drawn for a provider that sends none", () => {
    expect(effortField(options({ takes_effort: false, levels: [] }), "")).toEqual({
      kind: "hidden",
    });
  });

  it("is typed while the backend has not answered", () => {
    expect(effortField(null, "high")).toEqual({ kind: "text", placeholder: "inherit" });
  });
});

describe("a stored model choice and its effort", () => {
  it("keeps an effort that is set and drops a blank one", () => {
    expect(storedChoice({ provider: "openai", model: "m", effort: "high" })).toEqual({
      provider: "openai",
      model: "m",
      effort: "high",
    });
    expect(storedChoice({ provider: "openai", model: "m", effort: "" })).toEqual({
      provider: "openai",
      model: "m",
    });
  });

  it("drops the effort when the provider changes, and keeps it otherwise", () => {
    const row = { provider: "anthropic", model: "m", effort: "low" };
    expect(withProvider(row, "ollama")).toEqual({ provider: "ollama", model: "m" });
    expect(withProvider(row, "anthropic")).toEqual(row);
  });
});
