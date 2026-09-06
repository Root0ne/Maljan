"use client";

import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import {
  ADD_BUTTON,
  copyKey,
  mapKeyError,
  putEntry,
  removeEntry,
  type KeyError,
} from "./mapEditorHelpers";
import type {
  AgentDefinitionEntry,
  AgentProbeDetails,
  CatalogEntry,
  McpServerEntry,
  ProbeResult,
  SettingValue,
  ToolRefEntry,
} from "@/types/settings";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/** Re-seeded by the settings model, so they lock rather than delete. */
export const BUILTIN_AGENT_KEYS = new Set(["static", "dynamic", "network", "judge"]);
/** Roles that read a static provider; the others have nothing to point at. */
const PROVIDER_ROLES = new Set(["static", "generic"]);

export const EMPTY_DEFINITION: AgentDefinitionEntry = {
  role: "generic",
  label: "",
  prompt: "",
  tools: [],
  static_provider: null,
  enabled: true,
};

/**
 * One entry of `llm.agents`, mirroring `maljan.core.config.AgentLLMConfig`.
 * Absent from the map means "inherit `llm.provider`/the provider's own
 * `expert_model`/`judge_model`" — there is no per-definition storage for
 * this, `llm.agents` is a single JSON leaf of its own (`core.llm.agents`),
 * exactly like `core.mcp.servers`.
 */
export interface AgentLLMOverride {
  provider: string;
  model: string;
  temperature?: number | null;
}

/** What the card's LLM section needs to know about the two *global* leaves
 *  it falls back to display when a field is left blank. Both are computed
 *  once by the caller from `core_catalog()`'s actual keys: `llm.provider`
 *  is a real leaf, `llm.model` is not (models live per-provider, e.g.
 *  `llm.openai.expert_model`) — so `modelValue` is always `null` today, and
 *  the model field always shows the generic "inherits the global model"
 *  text. Kept symmetric rather than hard-coded so a future `llm.model`
 *  leaf needs no change here. */
export interface LlmGlobalFallback {
  /** `null` when `core.llm.provider` is not in the catalog; otherwise its
   *  choices (possibly empty), which switches the field from free text to
   *  a select. */
  providerChoices: string[] | null;
  /** The effective global provider, or `null` when the leaf doesn't exist. */
  providerValue: string | null;
  /** The effective global model, or `null` when no such leaf exists. */
  modelValue: string | null;
}

/**
 * The whole `core.agents.definitions` leaf, as a list of cards.
 *
 * One staged value for the whole map, exactly as `ServerMapEditor` stages the
 * whole server map: the PATCH body is the full dict, so sub-project A's apply
 * bar, hidden-dirty count and reset behaviour need no special case, and a
 * half-applied map cannot happen.
 *
 * A built-in card shows a lock and only its enabled switch, because that is
 * the only edit the settings model accepts. Its prompt is shown read-only from
 * the agent probe rather than reconstructed here — the built-in assembly
 * depends on the agent's static provider and only the API can say what it
 * comes to.
 */
export default function AgentDefinitionsEditor({
  entry,
  current,
  staged,
  servers,
  staticProviders,
  llmAgentsCurrent,
  llmAgentsStaged,
  llmGlobal,
  onChangeLlmAgents,
  errors,
  onChange,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  servers: Record<string, McpServerEntry>;
  staticProviders: string[];
  /** `core.llm.agents`'s own current/staged value — one JSON leaf for every
   *  agent's LLM override, staged as a whole exactly like `core.mcp.servers`
   *  (spec §2: "not stored on the definition"; §9: "LLM fields bound to
   *  llm.agents.<key>.*"). Distinct from `current`/`staged` above, which are
   *  `core.agents.definitions`'s own. */
  llmAgentsCurrent: SettingValue | undefined;
  llmAgentsStaged: unknown;
  llmGlobal: LlmGlobalFallback;
  onChangeLlmAgents: (value: Record<string, AgentLLMOverride>) => void;
  /** Validation errors from the last failed apply, keyed by the server's
   *  full dotted path (e.g. `core.agents.definitions.nameless.prompt`) —
   *  finer-grained than this leaf's own `entry.key`, so a bad field on one
   *  agent lands on that agent's card instead of a leaf-wide banner nobody
   *  can trace back to the offending definition. */
  errors: Record<string, string>;
  onChange: (value: Record<string, AgentDefinitionEntry>) => void;
}) {
  const value = (staged ?? current?.value ?? entry.default ?? {}) as Record<
    string,
    AgentDefinitionEntry
  >;
  const llmAgents = (llmAgentsStaged ?? llmAgentsCurrent?.value ?? {}) as Record<
    string,
    AgentLLMOverride
  >;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<KeyError | null>(null);
  const newKeyRef = useRef<HTMLInputElement | null>(null);
  const [probes, setProbes] = useState<Record<string, ProbeResult | "running">>({});
  const [manifests, setManifests] = useState<Record<string, string[]>>({});
  /** Set only for a model-only edit with no effective global provider to
   *  fall back to — see `putLlm` below. */
  const [llmErrors, setLlmErrors] = useState<Record<string, string>>({});

  const put = (key: string, next: Partial<AgentDefinitionEntry>) =>
    onChange(putEntry(value, key, next));

  const clearLlmError = (agentKey: string) =>
    setLlmErrors((e) => {
      if (!(agentKey in e)) return e;
      const n = { ...e };
      delete n[agentKey];
      return n;
    });

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
   *  a request the API would only reject. */
  const putLlm = (agentKey: string, next: Partial<AgentLLMOverride>) => {
    const base: AgentLLMOverride = llmAgents[agentKey] ?? { provider: "", model: "" };
    const merged: AgentLLMOverride = { ...base, ...next };
    if (!merged.provider && !merged.model) {
      clearLlmError(agentKey);
      const map = { ...llmAgents };
      delete map[agentKey];
      onChangeLlmAgents(map);
      return;
    }
    let provider = merged.provider;
    if (!provider && merged.model) {
      provider = llmGlobal.providerValue ?? "";
      if (!provider) {
        setLlmErrors((e) => ({
          ...e,
          [agentKey]: "set a provider — the global provider isn't configured either",
        }));
        return;
      }
    }
    clearLlmError(agentKey);
    const stored: AgentLLMOverride = { provider, model: merged.model };
    if (merged.temperature !== null && merged.temperature !== undefined) {
      stored.temperature = merged.temperature;
    }
    onChangeLlmAgents({ ...llmAgents, [agentKey]: stored });
  };

  const add = (from?: string) => {
    const at = from ?? ADD_BUTTON;
    // B5: an empty name box on a Clone means "name it after its source"; on
    // Add it is still a name the operator has to supply.
    const typed = newKey.trim();
    const key = typed === "" && from ? copyKey(from, value) : typed;
    const problem = mapKeyError(key, value, "agent");
    if (problem) {
      setKeyError({ at, message: problem });
      newKeyRef.current?.focus();
      return;
    }
    setKeyError(null);
    setNewKey("");
    const source = from ? value[from] : undefined;
    const sourceProbe = from ? probes[from] : undefined;
    const resolvedDetails =
      sourceProbe && sourceProbe !== "running" && sourceProbe.ok
        ? (sourceProbe.details as AgentProbeDetails | null)
        : null;
    onChange({
      ...value,
      [key]: source
        ? {
            ...source,
            label: source.label ? `${source.label} (copy)` : key,
            // A clone starts from what its source *resolves to*, so an
            // operator can see and edit the built-in prompt rather than
            // guessing it: the source's own `prompt` when it has one, else
            // the probe's resolved text once the source has been resolved,
            // else `null` — still "the built-in prompt" — with the editor's
            // usual hint to press Resolve first.
            prompt: source.prompt ?? resolvedDetails?.prompt ?? null,
            tools: source.tools.map((t) => ({ ...t })),
          }
        : { ...EMPTY_DEFINITION },
    });
    // A clone starts with the source's LLM override too, if it has one — the
    // override lives outside the definition, so cloning the definition alone
    // would silently drop it and leave the clone on the global default.
    if (from && llmAgents[from]) {
      onChangeLlmAgents({ ...llmAgents, [key]: { ...llmAgents[from] } });
    }
  };

  const remove = (key: string) => {
    if (BUILTIN_AGENT_KEYS.has(key)) {
      put(key, { enabled: false });
      return;
    }
    onChange(removeEntry(value, key));
  };

  const resolve = async (key: string) => {
    setProbes((p) => ({ ...p, [key]: "running" }));
    try {
      const result = await api.probeAgent(key, { "core.agents.definitions": value });
      setProbes((p) => ({ ...p, [key]: result }));
    } catch (e) {
      setProbes((p) => ({
        ...p,
        [key]: {
          ok: false,
          latency_ms: 0,
          detail: getErrorMessage(e),
          models: null,
          tools: null,
          details: null,
        },
      }));
    }
  };

  const loadManifest = async (server: string) => {
    try {
      const result = await api.testMcpServer(server, { "core.mcp.servers": servers });
      setManifests((m) => ({ ...m, [server]: result.tools ?? [] }));
    } catch {
      setManifests((m) => ({ ...m, [server]: [] }));
    }
  };

  const toggleRef = (key: string, ref: ToolRefEntry, on: boolean) => {
    const same = (a: ToolRefEntry) =>
      a.kind === ref.kind && a.server === ref.server && a.name === ref.name;
    const tools = value[key].tools;
    put(key, { tools: on ? [...tools, ref] : tools.filter((t) => !same(t)) });
  };

  const hasRef = (key: string, ref: ToolRefEntry) =>
    value[key].tools.some(
      (t) => t.kind === ref.kind && t.server === ref.server && t.name === ref.name
    );

  return (
    <div className="space-y-3" data-testid="agent-definitions-editor">
      {Object.entries(value).map(([key, agent]) => {
        const locked = BUILTIN_AGENT_KEYS.has(key);
        const result = probes[key];
        const details =
          result && result !== "running"
            ? ((result.details as AgentProbeDetails | null) ?? null)
            : null;
        const cardError = Object.entries(errors).find(([k]) =>
          k.startsWith(`${entry.key}.${key}.`)
        )?.[1];
        return (
          <div key={key} className="border border-border rounded p-3" data-agent={key}>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm text-text-primary font-mono">
                {key}
                <span className="ml-2 text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-border text-text-muted">
                  {agent.role}
                </span>
                {locked && (
                  <span className="ml-2 text-[10px] uppercase tracking-wider text-text-muted">
                    built in
                  </span>
                )}
              </span>
              <div className="flex items-center gap-3">
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${key} enabled`}
                    checked={agent.enabled}
                    onChange={(e) => put(key, { enabled: e.target.checked })}
                  />
                  enabled
                </label>
                <button
                  type="button"
                  className="text-xs text-accent-strong disabled:opacity-50"
                  disabled={result === "running"}
                  onClick={() => void resolve(key)}
                >
                  Resolve
                </button>
                {/* Spec §3.1: there is one judge and it cannot be cloned, so
                    the card that offers it does not offer Clone either. */}
                {agent.role !== "judge" && (
                  <button
                    type="button"
                    className="text-xs text-accent-strong"
                    onClick={() => add(key)}
                  >
                    Clone
                  </button>
                )}
                {!locked && (
                  <button
                    type="button"
                    className="text-xs text-text-secondary"
                    onClick={() => remove(key)}
                  >
                    Remove
                  </button>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <label className="block">
                <span className="text-text-muted">Label</span>
                <input
                  className={input}
                  aria-label={`${key} label`}
                  disabled={locked}
                  value={agent.label}
                  onChange={(e) => put(key, { label: e.target.value })}
                />
              </label>
              {PROVIDER_ROLES.has(agent.role) && (
                <label className="block">
                  <span className="text-text-muted">Static provider</span>
                  <select
                    className={input}
                    aria-label={`${key} static provider`}
                    disabled={locked}
                    value={agent.static_provider ?? ""}
                    onChange={(e) =>
                      put(key, { static_provider: e.target.value || null })
                    }
                  >
                    <option value="">Inherit from settings</option>
                    {staticProviders.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                </label>
              )}
              <label className="block sm:col-span-2">
                <span className="text-text-muted">
                  {locked ? "Prompt (built in, read-only)" : "Prompt"}
                </span>
                <textarea
                  className={input}
                  rows={4}
                  aria-label={`${key} prompt`}
                  disabled={locked}
                  placeholder={
                    agent.prompt === null ? "the built-in prompt for this role" : ""
                  }
                  value={
                    locked
                      ? (details?.prompt ??
                        "press Resolve to see the built-in prompt this agent receives")
                      : (agent.prompt ?? "")
                  }
                  onChange={(e) => put(key, { prompt: e.target.value })}
                />
              </label>
            </div>

            {/* The LLM lives outside the definition (`llm.agents.<key>.*`),
               so the built-in lock never applies here — even a built-in role
               may run on a different model than the global default. */}
            <fieldset className="mt-2 grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
              <legend className="text-text-muted col-span-full">
                LLM override (blank = inherit the global settings)
              </legend>
              <label className="block">
                <span className="text-text-muted">Provider</span>
                {llmGlobal.providerChoices !== null ? (
                  <select
                    className={input}
                    aria-label={`${key} llm provider`}
                    value={llmAgents[key]?.provider ?? ""}
                    onChange={(e) => putLlm(key, { provider: e.target.value })}
                  >
                    <option value="">
                      {llmGlobal.providerValue ? `Inherit (${llmGlobal.providerValue})` : "Inherit"}
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
                    aria-label={`${key} llm provider`}
                    placeholder="inherits the global provider"
                    value={llmAgents[key]?.provider ?? ""}
                    onChange={(e) => putLlm(key, { provider: e.target.value })}
                  />
                )}
              </label>
              <label className="block">
                <span className="text-text-muted">Model</span>
                <input
                  className={input}
                  aria-label={`${key} llm model`}
                  placeholder={
                    llmGlobal.modelValue
                      ? `inherits ${llmGlobal.modelValue}`
                      : "inherits the global model"
                  }
                  value={llmAgents[key]?.model ?? ""}
                  onChange={(e) => putLlm(key, { model: e.target.value })}
                />
              </label>
              <label className="block">
                <span className="text-text-muted">Temperature</span>
                <input
                  type="number"
                  step="0.1"
                  className={input}
                  aria-label={`${key} llm temperature`}
                  placeholder="inherit"
                  value={
                    llmAgents[key]?.temperature === null ||
                    llmAgents[key]?.temperature === undefined
                      ? ""
                      : String(llmAgents[key]!.temperature)
                  }
                  onChange={(e) => {
                    const raw = e.target.value;
                    if (raw === "") {
                      putLlm(key, { temperature: null });
                      return;
                    }
                    const parsed = parseFloat(raw);
                    if (!Number.isNaN(parsed)) putLlm(key, { temperature: parsed });
                  }}
                />
              </label>
            </fieldset>
            {llmErrors[key] && (
              <p className="text-[11px] text-status-red mt-1" role="alert">
                {llmErrors[key]}
              </p>
            )}

            <fieldset className="mt-2">
              <legend className="text-xs text-text-muted">Tools</legend>
              {agent.role === "generic" && !locked && (
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${key} provider tools`}
                    disabled={locked}
                    checked={hasRef(key, { kind: "provider", server: null, name: null })}
                    onChange={(e) =>
                      toggleRef(key, { kind: "provider", server: null, name: null }, e.target.checked)
                    }
                  />
                  its static provider&rsquo;s tools
                </label>
              )}
              {Object.keys(servers).map((server) => (
                <div key={server} className="mt-1">
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-text-secondary flex items-center gap-1">
                      <input
                        type="checkbox"
                        aria-label={`${key} server ${server}`}
                        disabled={locked}
                        checked={hasRef(key, { kind: "mcp", server, name: null })}
                        onChange={(e) =>
                          toggleRef(key, { kind: "mcp", server, name: null }, e.target.checked)
                        }
                      />
                      {server} (all allowed tools)
                    </label>
                    <button
                      type="button"
                      className="text-[11px] text-accent-strong"
                      onClick={() => void loadManifest(server)}
                    >
                      List tools
                    </button>
                  </div>
                  <div className="flex gap-3 flex-wrap ml-4">
                    {(manifests[server] ?? []).map((tool) => (
                      <label
                        key={tool}
                        className="text-xs text-text-secondary flex items-center gap-1"
                      >
                        <input
                          type="checkbox"
                          aria-label={`${key} tool ${server}.${tool}`}
                          disabled={locked}
                          checked={hasRef(key, { kind: "mcp", server, name: tool })}
                          onChange={(e) =>
                            toggleRef(key, { kind: "mcp", server, name: tool }, e.target.checked)
                          }
                        />
                        {tool}
                      </label>
                    ))}
                  </div>
                </div>
              ))}
            </fieldset>

            {result === "running" && (
              <p className="text-[11px] text-text-muted mt-2">resolving…</p>
            )}
            {result && result !== "running" && (
              <p
                className={`text-[11px] mt-2 ${result.ok ? "text-status-green" : "text-status-red"}`}
                role="status"
              >
                {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {result.detail}
                {details ? ` · prompt ${details.prompt_chars} chars` : ""}
              </p>
            )}
            {keyError?.at === key && (
              <p className="text-[11px] text-status-red mt-2 text-right" role="alert">
                {keyError.message}
              </p>
            )}
            {cardError && (
              <p className="text-[11px] text-status-red mt-2" role="alert">
                {cardError}
              </p>
            )}
          </div>
        );
      })}

      <div className="flex items-center gap-2">
        <input
          className={input}
          ref={newKeyRef}
          placeholder="new agent name"
          aria-label="new agent name"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
        />
        <button type="button" className="text-xs text-accent-strong" onClick={() => add()}>
          Add agent
        </button>
      </div>
      {keyError?.at === ADD_BUTTON && (
        <p className="text-[11px] text-status-red" role="alert">
          {keyError.message}
        </p>
      )}
    </div>
  );
}
