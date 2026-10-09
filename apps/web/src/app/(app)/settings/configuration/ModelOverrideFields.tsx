"use client";

import { useState } from "react";
import type { AgentLLMOverride, LlmGlobalFallback } from "./AgentDefinitionsEditor";
import EffortField from "./EffortField";
import {
  hasEndpoint,
  mergeEntry,
  moveChoice,
  storedChoice,
  withProvider,
  type ModelChoice,
} from "./modelList";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/**
 * The models an agent falls back to, in the order they are tried.
 *
 * The next model answers a turn only when the one before failed as a
 * provider; what a model said is never a reason to ask another, so the
 * editor says so where the list is edited. Each fallback passes the same
 * probe gate the first model does, which is why saving one asks for a probe.
 */
function FallbackModels({
  agentKey,
  rows,
  providerChoices,
  inputClass,
  onChange,
}: {
  agentKey: string;
  rows: ModelChoice[];
  providerChoices: string[] | null;
  inputClass: string;
  onChange: (rows: ModelChoice[]) => void;
}) {
  const put = (index: number, next: Partial<ModelChoice>) =>
    onChange(rows.map((row, i) => (i === index ? { ...row, ...next } : row)));
  const putProvider = (index: number, provider: string) =>
    onChange(rows.map((row, i) => (i === index ? withProvider(row, provider) : row)));
  return (
    <div className="mt-2 text-xs">
      <p className="text-text-muted">
        Fallback models, tried in order only when the model before fails as a provider — a
        refused connection, a timeout, a server error, a model the server does not have. A
        rejected answer is always sent back to the model that wrote it.
      </p>
      <ol className="space-y-1 mt-1" aria-label={`${agentKey} fallback models`}>
        {rows.map((row, index) => (
          <li key={index} className="grid grid-cols-1 sm:grid-cols-[1fr_1fr_1fr_1fr_auto] gap-1">
            {providerChoices !== null ? (
              <select
                className={inputClass}
                aria-label={`${agentKey} fallback ${index + 1} provider`}
                value={row.provider}
                onChange={(e) => putProvider(index, e.target.value)}
              >
                <option value="">provider</option>
                {providerChoices.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            ) : (
              <input
                className={inputClass}
                aria-label={`${agentKey} fallback ${index + 1} provider`}
                placeholder="provider"
                value={row.provider}
                onChange={(e) => putProvider(index, e.target.value)}
              />
            )}
            <input
              className={inputClass}
              aria-label={`${agentKey} fallback ${index + 1} model`}
              placeholder="model"
              value={row.model}
              onChange={(e) => put(index, { model: e.target.value })}
            />
            {hasEndpoint(row.provider) ? (
              <input
                className={inputClass}
                aria-label={`${agentKey} fallback ${index + 1} base url`}
                placeholder="base URL (blank = the provider's)"
                value={row.base_url ?? ""}
                onChange={(e) => put(index, { base_url: e.target.value })}
              />
            ) : (
              <span />
            )}
            {row.provider && row.model ? (
              <EffortField
                provider={row.provider}
                model={row.model}
                value={row.effort ?? ""}
                label={`${agentKey} fallback ${index + 1} effort`}
                inputClass={inputClass}
                onChange={(effort) => put(index, { effort })}
              />
            ) : (
              <span />
            )}
            <span className="flex gap-1">
              <button
                type="button"
                className="px-1 border border-border rounded disabled:opacity-40"
                aria-label={`move ${agentKey} fallback ${index + 1} up`}
                disabled={index === 0}
                onClick={() => onChange(moveChoice(rows, index, -1))}
              >
                ↑
              </button>
              <button
                type="button"
                className="px-1 border border-border rounded disabled:opacity-40"
                aria-label={`move ${agentKey} fallback ${index + 1} down`}
                disabled={index === rows.length - 1}
                onClick={() => onChange(moveChoice(rows, index, 1))}
              >
                ↓
              </button>
              <button
                type="button"
                className="px-1 border border-border rounded text-status-red"
                aria-label={`remove ${agentKey} fallback ${index + 1}`}
                onClick={() => onChange(rows.filter((_, i) => i !== index))}
              >
                ×
              </button>
            </span>
          </li>
        ))}
      </ol>
      <button
        type="button"
        className="mt-1 px-2 py-0.5 border border-border rounded"
        aria-label={`add a fallback model to ${agentKey}`}
        onClick={() => onChange([...rows, { provider: "", model: "" }])}
      >
        Add a fallback model
      </button>
    </div>
  );
}

/**
 * One `llm.agents` entry's model fields: provider, model, temperature, its
 * own effort, its own endpoint and its fallback list.
 *
 * An agent definition's detail draws it, and so does a role with no
 * definition (the mediator, the function summariser), whose entry is the
 * whole of what it has to configure. The entry is staged into the one
 * `core.llm.agents` leaf either way.
 */
export default function ModelOverrideFields({
  agentKey,
  llmAgents,
  onChangeLlmAgents,
  llmGlobal,
  probedModels = null,
  onEdited = () => {},
  legend = "Model override (blank = inherit the global settings)",
}: {
  agentKey: string;
  llmAgents: Record<string, AgentLLMOverride>;
  onChangeLlmAgents: (value: Record<string, AgentLLMOverride>) => void;
  llmGlobal: LlmGlobalFallback;
  /** Models the last probe listed, offered as suggestions on the model box. */
  probedModels?: string[] | null;
  /** Called with the key whose entry an edit is about to stage, so a probe
   *  result that described the old entry can be dropped. */
  onEdited?: (key: string) => void;
  legend?: string;
}) {
  /** Set only for a model-only edit with no effective global provider to
   *  fall back to — see `putLlm` below. */
  const [llmError, setLlmError] = useState<string | null>(null);
  const modelList = probedModels && probedModels.length > 0 ? `agent-models-${agentKey}` : undefined;

  /** Merges `next` into one agent's LLM override and stages the whole
   *  `core.llm.agents` map — removing the entry once provider and model are
   *  both empty, since an override with neither is nothing to keep (and
   *  `AgentLLMConfig` requires both when present). Temperature is omitted
   *  from the entry, not stored as `null`, when blank.
   *
   *  A model-only edit would otherwise stage `provider: ""`, which
   *  `AgentLLMConfig` rejects: the effective global `llm.provider` (staged
   *  over saved) fills in instead, and if even that is unavailable nothing
   *  is staged — an inline message asks for a provider rather than sending
   *  a request the API would only reject. The base URL is dropped when
   *  blank for the same reason temperature is. */
  const putLlm = (key: string, next: Partial<AgentLLMOverride>) => {
    const base: AgentLLMOverride = llmAgents[key] ?? { provider: "", model: "" };
    // An effort belongs to the provider it was chosen for, which for an
    // entry with a blank provider is the global one.
    const merged: AgentLLMOverride = mergeEntry(base, next, llmGlobal.providerValue);
    if (!merged.provider && !merged.model) {
      setLlmError(null);
      const map = { ...llmAgents };
      delete map[key];
      onChangeLlmAgents(map);
      return;
    }
    let provider = merged.provider;
    if (!provider && merged.model) {
      provider = llmGlobal.providerValue ?? "";
      if (!provider) {
        setLlmError("set a provider — the global provider isn't configured either");
        return;
      }
    }
    setLlmError(null);
    onEdited(key);
    const stored: AgentLLMOverride = { provider, model: merged.model };
    if (merged.temperature !== null && merged.temperature !== undefined) {
      stored.temperature = merged.temperature;
    }
    // Dropped rather than carried when the provider has no endpoint to
    // override: switching an entry to Anthropic would otherwise stage a
    // base_url the API rejects, from a field that is no longer on screen.
    if (merged.base_url && hasEndpoint(provider)) {
      stored.base_url = merged.base_url;
    }
    if (merged.effort && merged.effort.trim()) stored.effort = merged.effort.trim();
    // The list is carried whole: a row still being typed is kept on screen
    // (`draftFallbacks`) and staged once it names a provider and a model.
    const fallbacks = (merged.fallbacks ?? [])
      .map(storedChoice)
      .filter((c): c is ModelChoice => c !== null);
    if (fallbacks.length) stored.fallbacks = fallbacks;
    onChangeLlmAgents({ ...llmAgents, [key]: stored });
  };

  /** The fallback rows on screen for one agent: the staged list, or — while
   *  a row is still being typed and names no provider or model yet, so is
   *  not staged — the rows as typed. Once every row is complete the staged
   *  list is what shows, so a discarded edit does not linger on screen. */
  const [draftFallbacks, setDraftFallbacks] = useState<Record<string, ModelChoice[]>>({});
  const fallbackRows = (key: string): ModelChoice[] => {
    const draft = draftFallbacks[key];
    if (draft && draft.some((row) => storedChoice(row) === null)) return draft;
    return llmAgents[key]?.fallbacks ?? [];
  };
  const putFallbacks = (key: string, rows: ModelChoice[]) => {
    setDraftFallbacks((all) => ({ ...all, [key]: rows }));
    putLlm(key, { fallbacks: rows });
  };


  return (
    <fieldset className="border border-border rounded p-2">
      <legend className="text-xs text-text-muted px-1">{legend}</legend>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
        <label className="block">
          <span className="text-text-muted">Provider</span>
          {llmGlobal.providerChoices !== null ? (
            <select
              className={input}
              aria-label={`${agentKey} llm provider`}
              value={llmAgents[agentKey]?.provider ?? ""}
              onChange={(e) => putLlm(agentKey, { provider: e.target.value })}
            >
              <option value="">
                {llmGlobal.providerValue
                  ? `Inherit (${llmGlobal.providerValue})`
                  : "Inherit"}
              </option>
              {llmGlobal.providerChoices.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
          ) : (
            <input
              className={input}
              aria-label={`${agentKey} llm provider`}
              placeholder="inherits the global provider"
              value={llmAgents[agentKey]?.provider ?? ""}
              onChange={(e) => putLlm(agentKey, { provider: e.target.value })}
            />
          )}
        </label>
        <label className="block">
          <span className="text-text-muted">Model</span>
          <input
            className={input}
            aria-label={`${agentKey} llm model`}
            list={modelList}
            placeholder={
              llmGlobal.modelValue
                ? `inherits ${llmGlobal.modelValue}`
                : "inherits the global model"
            }
            value={llmAgents[agentKey]?.model ?? ""}
            onChange={(e) => putLlm(agentKey, { model: e.target.value })}
          />
          {modelList && (
            <datalist id={modelList}>
              {probedModels!.map((m) => (
                <option key={m} value={m} />
              ))}
            </datalist>
          )}
        </label>
        <label className="block">
          <span className="text-text-muted">Temperature</span>
          <input
            type="number"
            step="0.1"
            className={input}
            aria-label={`${agentKey} llm temperature`}
            placeholder="inherit"
            value={
              llmAgents[agentKey]?.temperature === null ||
              llmAgents[agentKey]?.temperature === undefined
                ? ""
                : String(llmAgents[agentKey]!.temperature)
            }
            onChange={(e) => {
              const raw = e.target.value;
              if (raw === "") {
                putLlm(agentKey, { temperature: null });
                return;
              }
              const parsed = parseFloat(raw);
              if (!Number.isNaN(parsed)) putLlm(agentKey, { temperature: parsed });
            }}
          />
        </label>
        {/* An effort lives on the agent's own entry, so it is offered
            once the entry names a model; its levels come from the
            backend for this provider and model, and a provider that
            sends none draws no field. */}
        {llmAgents[agentKey]?.model ? (
          <label className="block">
            <span className="text-text-muted">Reasoning effort</span>
            <EffortField
              provider={llmAgents[agentKey]?.provider || llmGlobal.providerValue || ""}
              model={llmAgents[agentKey]!.model}
              value={llmAgents[agentKey]?.effort ?? ""}
              label={`${agentKey} llm effort`}
              inputClass={input}
              onChange={(effort) => putLlm(agentKey, { effort })}
            />
          </label>
        ) : null}
        {/* Only the two providers that speak to a server the operator
            runs: Anthropic and Gemini are vendor APIs with no per-agent
            endpoint, and `AgentLLMConfig` rejects one set against them. */}
        {(() => {
          const effectiveProvider =
            llmAgents[agentKey]?.provider || llmGlobal.providerValue || "";
          if (effectiveProvider !== "openai" && effectiveProvider !== "ollama") {
            return null;
          }
          return (
            <label className="block">
              <span className="text-text-muted">Base URL</span>
              <input
                className={input}
                aria-label={`${agentKey} llm base url`}
                placeholder="http://127.0.0.1:8080/v1"
                value={llmAgents[agentKey]?.base_url ?? ""}
                onChange={(e) => putLlm(agentKey, { base_url: e.target.value })}
              />
            </label>
          );
        })()}
      </div>
      {llmError && (
        <p className="text-[11px] text-status-red mt-1" role="alert">
          {llmError}
        </p>
      )}
      {llmAgents[agentKey]?.model ? (
        <FallbackModels
          agentKey={agentKey}
          rows={fallbackRows(agentKey)}
          providerChoices={llmGlobal.providerChoices}
          inputClass={input}
          onChange={(rows) => putFallbacks(agentKey, rows)}
        />
      ) : null}
    </fieldset>
  );
}
