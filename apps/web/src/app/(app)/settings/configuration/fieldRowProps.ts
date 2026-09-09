import type { AgentDefinitionEntry, CatalogEntry, McpServerEntry } from "@/types/settings";
import type { AgentLLMOverride } from "./AgentDefinitionsEditor";
import type { SettingsContextValue } from "./SettingsContext";

/**
 * Builds the props `FieldRow` needs for one catalog entry, from the shared
 * settings context. Pulled out of the old `ConfigurationTab` so both the
 * per-group page here and Task 7's fuller group body build the same row the
 * same way.
 */
export function buildFieldRowProps(ctx: SettingsContextValue, entry: CatalogEntry) {
  const providerEntry = ctx.entriesByKey["core.llm.provider"];
  const modelEntry = ctx.entriesByKey["core.llm.model"];
  const llmGlobal = {
    providerChoices: providerEntry ? (providerEntry.choices ?? []) : null,
    providerValue: providerEntry
      ? String(ctx.effectiveValue("core.llm.provider") ?? "") || null
      : null,
    modelValue: modelEntry ? String(ctx.effectiveValue("core.llm.model") ?? "") || null : null,
  };

  return {
    entry,
    current: ctx.values[entry.key],
    staged: ctx.pending[entry.key],
    error: ctx.errors[entry.key],
    errors: ctx.errors,
    models: entry.probe === "llm" ? ctx.models : undefined,
    servers: (ctx.pending["core.mcp.servers"] ??
      ctx.values["core.mcp.servers"]?.value ??
      {}) as Record<string, McpServerEntry>,
    staticProviders: ctx.entriesByKey["core.static.provider"]?.choices ?? [],
    llmAgentsCurrent: ctx.values["core.llm.agents"],
    llmAgentsStaged: ctx.pending["core.llm.agents"],
    llmGlobal,
    onChangeLlmAgents: (v: Record<string, AgentLLMOverride>) => ctx.stage("core.llm.agents", v),
    definitions: (ctx.pending["core.agents.definitions"] ??
      ctx.values["core.agents.definitions"]?.value ??
      {}) as Record<string, AgentDefinitionEntry>,
    activeProfile: (ctx.pending["core.agents.profile"] ??
      ctx.values["core.agents.profile"]?.value ??
      "default") as string,
    onSetActive: (name: string) => ctx.stage("core.agents.profile", name),
    onChange: (v: unknown) => ctx.stage(entry.key, v),
    onUnstage: () => ctx.unstage(entry.key),
    onReset: () => void ctx.reset(entry.key),
  };
}
