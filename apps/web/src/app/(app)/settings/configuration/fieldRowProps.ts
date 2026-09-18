import type { CatalogEntry, McpServerEntry } from "@/types/settings";
import type { AgentLLMOverride } from "./AgentDefinitionsEditor";
import {
  AGENT_DEFINITIONS_KEY,
  displayedDefinitions,
  type DefinitionMap,
  type StagedDefinitionMap,
} from "./agentStaging";
import type { SettingsContextValue } from "./SettingsContext";

/**
 * Builds the props `FieldRow` needs for one catalog entry, from the shared
 * settings context. Pulled out of the old `ConfigurationTab` so both the
 * per-group page here and the fuller group body build the same row the
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
    // Advisory notes from the last apply. They live on the result rather than
    // on the staged edits because a warning is about the configuration that
    // resulted, and the PATCH that produces one often names no team at all —
    // switching the static provider to `none` is exactly that patch.
    warnings: ctx.lastResult?.warnings ?? {},
    models: entry.probe === "llm" ? ctx.models : undefined,
    servers: (ctx.pending["core.mcp.servers"] ??
      ctx.values["core.mcp.servers"]?.value ??
      {}) as Record<string, McpServerEntry>,
    staticProviders: ctx.entriesByKey["core.static.provider"]?.choices ?? [],
    llmAgentsCurrent: ctx.values["core.llm.agents"],
    llmAgentsStaged: ctx.pending["core.llm.agents"],
    llmGlobal,
    onChangeLlmAgents: (v: Record<string, AgentLLMOverride>) => ctx.stage("core.llm.agents", v),
    // Read through the pair, like every other reader of this leaf. A staged
    // built-in carries its role and its switch and nothing else, so taking the
    // pending value raw left the stage cards and the analyst picker naming
    // five built-ins by key — "static" where they had read "Static analyst" a
    // moment before — for as long as an agent-map edit was unapplied.
    definitions: displayedDefinitions(
      (ctx.pending[AGENT_DEFINITIONS_KEY] ?? null) as StagedDefinitionMap | null,
      (ctx.values[AGENT_DEFINITIONS_KEY]?.value ?? {}) as DefinitionMap,
    ),
    activeProfile: (ctx.pending["core.agents.profile"] ??
      ctx.values["core.agents.profile"]?.value ??
      "default") as string,
    onSetActive: (name: string) => ctx.stage("core.agents.profile", name),
    onChange: (v: unknown) => ctx.stage(entry.key, v),
    onUnstage: () => ctx.unstage(entry.key),
    onReset: () => void ctx.reset(entry.key),
  };
}
