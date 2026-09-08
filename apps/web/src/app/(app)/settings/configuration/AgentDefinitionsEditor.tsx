"use client";

import { useRef, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import Dot from "./Dot";
import {
  ADD_BUTTON,
  copyKey,
  deepEqual,
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
/** The roles a custom definition may take. `judge` is missing on purpose:
 *  there is exactly one judge and it is a built-in, so offering the role here
 *  would only produce a definition the settings model rejects. */
const ROLE_CHOICES: AgentDefinitionEntry["role"][] = [
  "static", "dynamic", "network", "generic",
];

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

/** What the detail's LLM section needs to know about the two *global* leaves
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
 * The whole `core.agents.definitions` leaf, as a master–detail editor.
 *
 * A card per agent stacked down the page put every prompt textarea, every LLM
 * override and every server's tool list on screen at once, so the leaf was as
 * tall as the number of agents times the number of servers. The list on the
 * left carries only what tells one agent from another — key, role, whether it
 * is a built-in, whether it is enabled, whether it differs from what is saved,
 * whether the last apply rejected it, and the last resolve verdict — and the
 * selected agent's form fills the right-hand side in four named sections.
 *
 * One staged value for the whole map, exactly as `ServerMapEditor` stages the
 * whole server map: the PATCH body is the full dict, so sub-project A's apply
 * bar, hidden-dirty count and reset behaviour need no special case, and a
 * half-applied map cannot happen. The per-agent LLM override rides on its own
 * leaf (`core.llm.agents`) and is staged as a whole the same way.
 *
 * A built-in shows a lock and only its enabled switch, because that is the
 * only edit the settings model accepts. Its prompt is shown read-only from
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
  /** Validation errors from the last failed apply, keyed by the agent's
   *  full dotted path (e.g. `core.agents.definitions.nameless.prompt`) —
   *  finer-grained than this leaf's own `entry.key`, so a bad field on one
   *  agent lands under that field on that agent's detail instead of a
   *  leaf-wide banner nobody can trace back to the offending definition. */
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
  /** What is stored right now, for the "changed" dot. An agent differs when
   *  either of the two leaves it spans has been edited: the definition itself,
   *  or its entry in the LLM override map. */
  const savedDefs = (current?.value ?? entry.default ?? {}) as Record<
    string,
    AgentDefinitionEntry
  >;
  const savedLlm = (llmAgentsCurrent?.value ?? {}) as Record<string, AgentLLMOverride>;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<KeyError | null>(null);
  const newKeyRef = useRef<HTMLInputElement | null>(null);
  const [probes, setProbes] = useState<Record<string, ProbeResult | "running">>({});
  const [manifests, setManifests] = useState<Record<string, string[]>>({});
  /** Set only for a model-only edit with no effective global provider to
   *  fall back to — see `putLlm` below. */
  const [llmErrors, setLlmErrors] = useState<Record<string, string>>({});
  /** The agent the detail pane shows. Null until something is picked, and a
   *  key that has since been removed falls back to the first one. */
  const [picked, setPicked] = useState<string | null>(null);

  const keys = Object.keys(value);
  const selected = picked !== null && picked in value ? picked : (keys[0] ?? null);

  /* B6 (dev audit 2026-09-06): a resolved prompt and tool list describe the
   * definition as it stood when Resolve was pressed. Editing what resolution
   * reads — the prompt, the tool refs, the static provider, the role — leaves
   * that status line describing something else, so it is dropped with the
   * edit. The label and the enabled switch change nothing resolution reads. */
  const RESOLVE_INPUTS = new Set<keyof AgentDefinitionEntry>([
    "role", "prompt", "tools", "static_provider",
  ]);

  const clearProbe = (key: string) =>
    setProbes((p) => {
      if (!(key in p)) return p;
      const n = { ...p };
      delete n[key];
      return n;
    });

  const put = (key: string, next: Partial<AgentDefinitionEntry>) => {
    if (Object.keys(next).some((k) => RESOLVE_INPUTS.has(k as keyof AgentDefinitionEntry))) {
      clearProbe(key);
    }
    onChange(putEntry(value, key, next));
  };

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
    clearProbe(agentKey);
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
    // The new agent is what the operator wants to edit next, so the detail
    // pane follows it rather than staying on whatever was selected.
    setPicked(key);
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

  /* B2 (dev audit 2026-09-06): the API qualifies an agent-map error with the
   * leaf it belongs to, and it points either at one field
   * (`core.agents.definitions.<key>.<field>`) or at the whole entry
   * (`core.agents.definitions.<key>`, for a name that is not a slug or an
   * entry that is not an object). Matching the field form alone left the
   * entry-level message with nothing to land on. */
  const anyErrorFor = (key: string): string | undefined =>
    Object.entries(errors).find(
      ([k]) => k === `${entry.key}.${key}` || k.startsWith(`${entry.key}.${key}.`)
    )?.[1];
  /** The message the API put on one named field, so it can be rendered under
   *  that field rather than at the foot of the detail. */
  const fieldErrorFor = (key: string, field: string): string | undefined =>
    errors[`${entry.key}.${key}.${field}`];

  const fieldError = (field: string) =>
    selected === null ? undefined : fieldErrorFor(selected, field);

  const FieldError = ({ field }: { field: string }) => {
    const message = fieldError(field);
    if (!message) return null;
    return (
      <span className="block text-[11px] text-status-red mt-1" role="alert">
        {message}
      </span>
    );
  };

  const agent = selected === null ? null : value[selected];
  const locked = selected !== null && BUILTIN_AGENT_KEYS.has(selected);
  const result = selected === null ? undefined : probes[selected];
  const details =
    result && result !== "running"
      ? ((result.details as AgentProbeDetails | null) ?? null)
      : null;
  /** The entry-level message only: the field-level ones are rendered under
   *  the fields they name. */
  const entryError = selected === null ? undefined : errors[`${entry.key}.${selected}`];
  /** Models the last resolve reported, offered as suggestions on the model
   *  box — the override is still free text, since a provider may serve a
   *  model the probe did not list. */
  const probedModels =
    result && result !== "running" && result.models && result.models.length > 0
      ? result.models
      : null;
  const modelList = probedModels && selected ? `agent-models-${selected}` : undefined;

  return (
    <div
      className="grid md:grid-cols-[260px_minmax(0,1fr)] gap-4"
      data-testid="agent-definitions-editor"
    >
      <div className="min-w-0">
        <ul
          role="listbox"
          aria-label="Agents"
          className="border border-border rounded divide-y divide-border"
        >
          {keys.map((key) => {
            const item = value[key];
            const itemResult = probes[key];
            const verdict =
              itemResult && itemResult !== "running" ? (itemResult.ok ? "ok" : "failed") : null;
            const changed =
              !deepEqual(item, savedDefs[key]) || !deepEqual(llmAgents[key], savedLlm[key]);
            return (
              <li
                key={key}
                role="option"
                data-agent={key}
                aria-selected={key === selected}
                tabIndex={key === selected ? 0 : -1}
                onClick={() => setPicked(key)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setPicked(key);
                  }
                }}
                className={`px-2 py-1.5 cursor-pointer focus:outline-none focus:ring-1 focus:ring-accent ${
                  key === selected ? "bg-accent/10" : "hover:bg-bg-deep"
                }`}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Dot
                    label={item.enabled ? "enabled" : "disabled"}
                    className={item.enabled ? "bg-status-green" : "bg-border"}
                  />
                  <span className="text-sm font-mono text-text-primary truncate">{key}</span>
                  {changed && <Dot label="changed" className="bg-accent-strong" />}
                  {anyErrorFor(key) && <Dot label="invalid" className="bg-status-red" />}
                </div>
                <div className="flex items-center gap-2 text-[11px] text-text-muted pl-3.5">
                  <span>{item.role}</span>
                  {BUILTIN_AGENT_KEYS.has(key) && <span>built in</span>}
                  {verdict && (
                    <span
                      className={verdict === "ok" ? "text-status-green" : "text-status-red"}
                    >
                      {verdict}
                    </span>
                  )}
                </div>
              </li>
            );
          })}
          {keys.length === 0 && (
            <li className="px-2 py-1.5 text-xs text-text-muted">no agents configured</li>
          )}
        </ul>

        {/* One name box for both buttons, as the footer input always was: Add
            needs a name, Clone takes one when it is given and falls back to
            `<source>_copy` when it is not. */}
        <div className="flex items-center gap-2 mt-2">
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
          <p className="text-[11px] text-status-red mt-1" role="alert">
            {keyError.message}
          </p>
        )}
      </div>

      {selected !== null && agent && (
        <section
          key={selected}
          data-agent-detail={selected}
          aria-label={`Agent ${selected}`}
          className="min-w-0 border border-border rounded p-3 space-y-3"
        >
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="text-sm text-text-primary font-mono">
              {selected}
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
                  aria-label={`${selected} enabled`}
                  checked={agent.enabled}
                  onChange={(e) => put(selected, { enabled: e.target.checked })}
                />
                enabled
              </label>
              <button
                type="button"
                className="text-xs text-accent-strong disabled:opacity-50"
                disabled={result === "running"}
                onClick={() => void resolve(selected)}
              >
                Resolve
              </button>
              {/* Spec §3.1: there is one judge and it cannot be cloned, so the
                  detail that offers it does not offer Clone either. */}
              {agent.role !== "judge" && (
                <button
                  type="button"
                  className="text-xs text-accent-strong"
                  onClick={() => add(selected)}
                >
                  Clone
                </button>
              )}
              <button
                type="button"
                className="text-xs text-text-secondary"
                onClick={() => remove(selected)}
              >
                {locked ? "Disable" : "Remove"}
              </button>
            </div>
          </div>

          {result === "running" && <p className="text-[11px] text-text-muted">resolving…</p>}
          {result && result !== "running" && (
            <p
              className={`text-[11px] ${result.ok ? "text-status-green" : "text-status-red"}`}
              role="status"
            >
              {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {result.detail}
              {details ? ` · prompt ${details.prompt_chars} chars` : ""}
            </p>
          )}
          {keyError?.at === selected && (
            <p className="text-[11px] text-status-red" role="alert">
              {keyError.message}
            </p>
          )}
          {entryError && (
            <p className="text-[11px] text-status-red" role="alert">
              {entryError}
            </p>
          )}

          <fieldset className="border border-border rounded p-2">
            <legend className="text-xs text-text-muted px-1">Identity</legend>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <label className="block">
                <span className="text-text-muted">Label</span>
                <input
                  className={input}
                  aria-label={`${selected} label`}
                  disabled={locked}
                  value={agent.label}
                  onChange={(e) => put(selected, { label: e.target.value })}
                />
                <FieldError field="label" />
              </label>
              {/* A built-in's role is what makes it that built-in, so only a
                  custom definition may choose one. */}
              {!locked && (
                <label className="block">
                  <span className="text-text-muted">Role</span>
                  <select
                    className={input}
                    aria-label={`${selected} role`}
                    value={agent.role}
                    onChange={(e) =>
                      put(selected, { role: e.target.value as AgentDefinitionEntry["role"] })
                    }
                  >
                    {/* A cloned built-in can carry a role this list would not
                        otherwise offer; it stays selectable rather than
                        silently switching to the first choice. */}
                    {(ROLE_CHOICES.includes(agent.role)
                      ? ROLE_CHOICES
                      : [agent.role, ...ROLE_CHOICES]
                    ).map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                  <FieldError field="role" />
                </label>
              )}
              {PROVIDER_ROLES.has(agent.role) && (
                <label className="block">
                  <span className="text-text-muted">Static provider</span>
                  <select
                    className={input}
                    aria-label={`${selected} static provider`}
                    disabled={locked}
                    value={agent.static_provider ?? ""}
                    onChange={(e) => put(selected, { static_provider: e.target.value || null })}
                  >
                    <option value="">Inherit from settings</option>
                    {staticProviders.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                  <FieldError field="static_provider" />
                </label>
              )}
            </div>
          </fieldset>

          <fieldset className="border border-border rounded p-2">
            <legend className="text-xs text-text-muted px-1">
              {locked ? "Prompt (built in, read-only)" : "Prompt"}
            </legend>
            <div className="block text-xs">
              <textarea
                className={input}
                rows={locked ? 6 : 8}
                aria-label={`${selected} prompt`}
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
                onChange={(e) => put(selected, { prompt: e.target.value })}
              />
              <FieldError field="prompt" />
            </div>
          </fieldset>

          {/* The LLM lives outside the definition (`llm.agents.<key>.*`), so
              the built-in lock never applies here — even a built-in role may
              run on a different model than the global default. */}
          <fieldset className="border border-border rounded p-2">
            <legend className="text-xs text-text-muted px-1">
              Model override (blank = inherit the global settings)
            </legend>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
              <label className="block">
                <span className="text-text-muted">Provider</span>
                {llmGlobal.providerChoices !== null ? (
                  <select
                    className={input}
                    aria-label={`${selected} llm provider`}
                    value={llmAgents[selected]?.provider ?? ""}
                    onChange={(e) => putLlm(selected, { provider: e.target.value })}
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
                    aria-label={`${selected} llm provider`}
                    placeholder="inherits the global provider"
                    value={llmAgents[selected]?.provider ?? ""}
                    onChange={(e) => putLlm(selected, { provider: e.target.value })}
                  />
                )}
              </label>
              <label className="block">
                <span className="text-text-muted">Model</span>
                <input
                  className={input}
                  aria-label={`${selected} llm model`}
                  list={modelList}
                  placeholder={
                    llmGlobal.modelValue
                      ? `inherits ${llmGlobal.modelValue}`
                      : "inherits the global model"
                  }
                  value={llmAgents[selected]?.model ?? ""}
                  onChange={(e) => putLlm(selected, { model: e.target.value })}
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
                  aria-label={`${selected} llm temperature`}
                  placeholder="inherit"
                  value={
                    llmAgents[selected]?.temperature === null ||
                    llmAgents[selected]?.temperature === undefined
                      ? ""
                      : String(llmAgents[selected]!.temperature)
                  }
                  onChange={(e) => {
                    const raw = e.target.value;
                    if (raw === "") {
                      putLlm(selected, { temperature: null });
                      return;
                    }
                    const parsed = parseFloat(raw);
                    if (!Number.isNaN(parsed)) putLlm(selected, { temperature: parsed });
                  }}
                />
              </label>
            </div>
            {llmErrors[selected] && (
              <p className="text-[11px] text-status-red mt-1" role="alert">
                {llmErrors[selected]}
              </p>
            )}
          </fieldset>

          {/* The tool refs are a two-level thing — a server, and the tools
              under it — so they are drawn as one: a server node carries its
              "everything this server allows" box and, once its manifest has
              been listed, its own tools indented beneath it. */}
          <fieldset className="border border-border rounded p-2">
            <legend className="text-xs text-text-muted px-1">Tools</legend>
            <ul role="tree" aria-label={`${selected} tools`} className="space-y-1">
              {agent.role === "generic" && !locked && (
                <li
                  role="treeitem"
                  aria-selected={hasRef(selected, {
                    kind: "provider",
                    server: null,
                    name: null,
                  })}
                >
                  <label className="text-xs text-text-secondary flex items-center gap-1">
                    <input
                      type="checkbox"
                      aria-label={`${selected} provider tools`}
                      checked={hasRef(selected, { kind: "provider", server: null, name: null })}
                      onChange={(e) =>
                        toggleRef(
                          selected,
                          { kind: "provider", server: null, name: null },
                          e.target.checked
                        )
                      }
                    />
                    its static provider&rsquo;s tools
                  </label>
                </li>
              )}
              {Object.keys(servers).map((server) => {
                const listed = manifests[server];
                return (
                  <li
                    key={server}
                    role="treeitem"
                    aria-expanded={listed !== undefined}
                    aria-selected={hasRef(selected, { kind: "mcp", server, name: null })}
                  >
                    <div className="flex items-center gap-2">
                      <label className="text-xs text-text-secondary flex items-center gap-1">
                        <input
                          type="checkbox"
                          aria-label={`${selected} server ${server}`}
                          disabled={locked}
                          checked={hasRef(selected, { kind: "mcp", server, name: null })}
                          onChange={(e) =>
                            toggleRef(
                              selected,
                              { kind: "mcp", server, name: null },
                              e.target.checked
                            )
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
                    {listed && listed.length > 0 && (
                      <ul role="group" className="ml-4 mt-0.5 flex gap-3 flex-wrap">
                        {listed.map((tool) => (
                          <li
                            key={tool}
                            role="treeitem"
                            aria-selected={hasRef(selected, { kind: "mcp", server, name: tool })}
                          >
                            <label className="text-xs text-text-secondary flex items-center gap-1">
                              <input
                                type="checkbox"
                                aria-label={`${selected} tool ${server}.${tool}`}
                                disabled={locked}
                                checked={hasRef(selected, { kind: "mcp", server, name: tool })}
                                onChange={(e) =>
                                  toggleRef(
                                    selected,
                                    { kind: "mcp", server, name: tool },
                                    e.target.checked
                                  )
                                }
                              />
                              {tool}
                            </label>
                          </li>
                        ))}
                      </ul>
                    )}
                    {listed && listed.length === 0 && (
                      <p className="ml-4 text-[11px] text-text-muted">
                        this server reported no tools
                      </p>
                    )}
                  </li>
                );
              })}
            </ul>
            {Object.keys(servers).length === 0 && (
              <p className="text-xs text-text-muted">no tool servers configured</p>
            )}
            <FieldError field="tools" />
          </fieldset>
        </section>
      )}
    </div>
  );
}
