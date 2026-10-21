"use client";

import { probeDetail } from "@/lib/probeDetail";
import { manifestOutcome } from "./manifestOutcome";
import { ProbeGenerations } from "./probeGenerations";
import { useRef, useState } from "react";
import { Bot } from "lucide-react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { agentDisplayName, agentKeySuffix } from "./agentNames";
import type { ModelChoice } from "./modelList";
import ModelOverrideFields from "./ModelOverrideFields";
import RoleModelDetail from "./RoleModelDetail";
import { ROLE_ENTRIES, roleEntryChanged, roleKeyError } from "./roleEntries";
import {
  builtinAgentKeys as builtinKeySet,
  cloneDefinition,
  displayedDefinitions,
  stagedDefinitions,
  type StagedDefinitionMap,
} from "./agentStaging";
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
import {
  capabilitiesReaching,
  capabilityRef,
  holdsServer,
  offeredCapabilities,
  sameToolRef,
  withoutServer,
  type CapabilityServers,
} from "./capabilityRefs";
import { SANDBOX_REF, choiceRows, toggleChoice } from "./choiceRows";
import type {
  AgentDefinitionEntry,
  AgentProbeDetails,
  CatalogEntry,
  McpServerEntry,
  ProbeResult,
  SettingValue,
  ToolRefEntry,
} from "@/types/settings";

/** The console tabs an agent may declare (`core.config.AGENT_TABS`). */
const AGENT_TABS = ["identity", "static", "dynamic", "network", "persistence"] as const;

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/** Roles that read a static provider; the others have nothing to point at. */
/* The roles that pick a static provider of their own: the built-in static
   analyst, and the two that are a prompt rather than a class. A `lead` is
   the same class as a generic agent, so the API takes a provider reference
   on it and the console has to be able to express one. */
const PROVIDER_ROLES = new Set(["static", "generic", "lead"]);
/** The roles that may turn the ATT&CK technique line off: the two that are a
 *  prompt rather than a class (`config.PROMPT_ROLES`). A built-in role keeps
 *  its own claim format and the settings model refuses the switch there. */
const TECHNIQUE_LINE_ROLES = new Set(["generic", "lead"]);

/** `definition` with the ATT&CK technique line on or off. On is stored as no
 *  field at all, which is how the API serves a definition that keeps it on,
 *  so turning it off and on again leaves the definition exactly as loaded. */
export function withTechniqueLine(
  definition: AgentDefinitionEntry,
  on: boolean
): AgentDefinitionEntry {
  const next = { ...definition };
  delete next.attck_techniques;
  return on ? next : { ...next, attck_techniques: false };
}
/** The roles a custom definition may take. `judge` and `report` are missing on
 *  purpose: there is exactly one of each and both are built-ins, so offering
 *  either here would only produce a definition the settings model rejects. */
const ROLE_CHOICES: AgentDefinitionEntry["role"][] = [
  "static", "dynamic", "network", "generic", "lead",
];
/** The roles an agent may be asked to work for another: the judge and the
 *  reporter are not analysts and the settings model refuses a reference to
 *  either. */
const ASKABLE_ROLES = new Set(["static", "dynamic", "network", "generic", "lead"]);

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
  /** A per-agent endpoint, so two agents can sit on two different local
   *  servers. Only a provider that declares one accepts it; the provider's
   *  API key stays global. */
  base_url?: string | null;
  /** This agent's own reasoning effort for its first model; absent inherits
   *  the provider's global one. The levels come from the backend. */
  effort?: string | null;
  /** The rest of the agent's ordered model list: tried in order only when
   *  the model before fails as a provider (a refused connection, a timeout,
   *  a 5xx, a model the server does not have) — never on what a model said.
   *  Absent or empty is the single-model form. */
  fallbacks?: ModelChoice[];
  /** This agent's own spend ceiling (USD), counted over every model of its
   *  list; once reached it makes no further model call. Absent is none. */
  max_spend_usd?: number | null;
  /** The tokens its calls of a model with no known price may use. Absent is
   *  none. */
  max_unpriced_tokens?: number | null;
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
  /** The providers an agent may give an endpoint of its own, as each
   *  provider declares in the settings schema. */
  endpointProviders?: ReadonlySet<string>;
}

/* A resolved prompt and tool list describe the
 * definition as it stood when Resolve was pressed. Editing what resolution
 * reads — the prompt, the tool refs, the static provider, the role — leaves
 * that status line describing something else, so it is dropped with the
 * edit. The label and the enabled switch change nothing resolution reads. */
const RESOLVE_INPUTS = new Set<keyof AgentDefinitionEntry>([
  "role", "prompt", "tools", "static_provider",
]);

/**
 * A whole number a budget box may hold, or `null` for "inherit".
 *
 * Anything that is not a whole number of at least one — an empty box, a `0`, a
 * minus sign on its own — is `null`, which stages *inherit*: the field is
 * cleared and the agent falls back to the deployment's budget. Nothing
 * unstageable is ever staged, so the API is never sent a `NaN` or a value its
 * own bound would refuse.
 */
function wholeNumber(raw: string): number | null {
  if (raw.trim() === "") return null;
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed >= 1 ? parsed : null;
}

/** One field's validation message, under the field the API named. */
function FieldError({ message }: { message?: string }) {
  if (!message) return null;
  return (
    <span className="block text-[11px] text-status-red mt-1" role="alert">
      {message}
    </span>
  );
}

/** Which blocks of the detail pane to draw. The console editor draws all but
 *  `resolve`, whose button and verdict it carries in its header; a guide step
 *  draws the one its step is about. */
export type AgentSection = "header" | "identity" | "prompt" | "model" | "tools" | "resolve";

const EDITOR_AGENT_SECTIONS: AgentSection[] = [
  "header", "identity", "prompt", "model", "tools",
];

/**
 * What Resolve knows about one definition map, and about the agent whose
 * detail is on screen, plus the per-server tool manifests the tools tree
 * lists on demand.
 *
 * The state is a map rather than a single result because the console's list
 * shows a verdict per agent; `result`/`details` are that map read at
 * `agentKey`, so a guide step that only ever holds one agent reads them and
 * ignores the rest.
 */
export interface AgentResolveApi {
  probes: Record<string, ProbeResult | "running">;
  result: ProbeResult | "running" | undefined;
  /** The resolved prompt and tool list of the focused agent, when it resolved. */
  details: AgentProbeDetails | null;
  /** Tool names each server reported, once "List tools" asked it. */
  manifests: Record<string, string[]>;
  /** Why a server's tools could not be listed, by server. */
  manifestErrors: Record<string, string>;
  resolve: (key: string) => Promise<void>;
  loadManifest: (server: string, servers: Record<string, McpServerEntry>) => Promise<void>;
  clearProbe: (key: string) => void;
  /** Called before an edit is staged: drops a result the edit invalidates. */
  noteEdit: (key: string, next: Partial<AgentDefinitionEntry>) => void;
}

/** The resolve half of the agent detail, so the console editor and a guide
 *  step can each own an instance without duplicating the staleness rule. */
export function useAgentResolve(
  agentKey: string | null,
  definitions: Record<string, AgentDefinitionEntry>
): AgentResolveApi {
  const [probes, setProbes] = useState<Record<string, ProbeResult | "running">>({});
  const [manifests, setManifests] = useState<Record<string, string[]>>({});
  const [manifestErrors, setManifestErrors] = useState<Record<string, string>>({});

  // A probe that lands after an edit to what it read is discarded: the edit
  // bumps the key's generation, and an answer is kept only under the one it
  // was asked in.
  const probeGens = useRef(new ProbeGenerations());

  const clearProbe = (key: string) => {
    probeGens.current.bump(key);
    setProbes((p) => {
      if (!(key in p)) return p;
      const n = { ...p };
      delete n[key];
      return n;
    });
  };

  const noteEdit = (key: string, next: Partial<AgentDefinitionEntry>) => {
    if (Object.keys(next).some((k) => RESOLVE_INPUTS.has(k as keyof AgentDefinitionEntry))) {
      clearProbe(key);
    }
  };

  const resolve = async (key: string) => {
    const taken = probeGens.current.take(key);
    const keep = (answer: ProbeResult) => {
      if (!probeGens.current.isCurrent(key, taken)) return;
      setProbes((p) => ({ ...p, [key]: answer }));
    };
    setProbes((p) => ({ ...p, [key]: "running" }));
    try {
      keep(await api.probeAgent(key, { "core.agents.definitions": definitions }));
    } catch (e) {
      keep({
        ok: false,
        latency_ms: 0,
        detail: getErrorMessage(e),
        models: null,
        tools: null,
        details: null,
      });
    }
  };

  const loadManifest = async (server: string, servers: Record<string, McpServerEntry>) => {
    const fail = (error: string) => {
      setManifests((m) => {
        const next = { ...m };
        delete next[server];
        return next;
      });
      setManifestErrors((m) => ({ ...m, [server]: error }));
    };
    try {
      const outcome = manifestOutcome(await api.testMcpServer(server, { "core.mcp.servers": servers }));
      if ("error" in outcome) return fail(outcome.error);
      setManifests((m) => ({ ...m, [server]: outcome.tools }));
      setManifestErrors((m) => {
        const next = { ...m };
        delete next[server];
        return next;
      });
    } catch (e) {
      fail(getErrorMessage(e));
    }
  };

  const result = agentKey === null ? undefined : probes[agentKey];
  return {
    probes,
    result,
    details:
      result && result !== "running"
        ? ((result.details as AgentProbeDetails | null) ?? null)
        : null,
    manifests,
    manifestErrors,
    resolve,
    loadManifest,
    clearProbe,
    noteEdit,
  };
}

/**
 * One agent's form: the header, its identity, its prompt, its model override
 * and its tool tree, in that order, with Resolve available either from the
 * header or as a section of its own.
 *
 * The console renders every section of it beside its agent list; a guide step
 * renders one section at a time for the agent the guide is building, staging
 * into the same two leaves — `core.agents.definitions` and `core.llm.agents` —
 * through the same two callbacks. There is one copy of these fields, so a rule
 * added here reaches both.
 */
export function AgentDetail({
  agentKey,
  definitions,
  onChange,
  llmAgents,
  onChangeLlmAgents,
  llmGlobal,
  servers,
  staticProviders,
  resolve,
  errors = {},
  entryKey = "core.agents.definitions",
  sections = EDITOR_AGENT_SECTIONS,
  onClone,
  keyErrorMessage,
  capabilityServers = {},
  dataSourceChoices = [],
  builtinAgentKeys,
  alwaysEnabledAgentKeys,
}: {
  agentKey: string;
  /** The whole staged definition map, staged as a whole. */
  definitions: Record<string, AgentDefinitionEntry>;
  onChange: (value: Record<string, AgentDefinitionEntry>) => void;
  /** `core.llm.agents`'s effective value — one JSON leaf for every agent's
   *  LLM override, staged as a whole exactly like the definitions. */
  llmAgents: Record<string, AgentLLMOverride>;
  onChangeLlmAgents: (value: Record<string, AgentLLMOverride>) => void;
  llmGlobal: LlmGlobalFallback;
  servers: Record<string, McpServerEntry>;
  staticProviders: string[];
  resolve: AgentResolveApi;
  /** Validation errors from the last failed apply, keyed by the agent's full
   *  dotted path (e.g. `core.agents.definitions.nameless.prompt`). */
  errors?: Record<string, string>;
  /** The leaf those errors are keyed under. */
  entryKey?: string;
  sections?: AgentSection[];
  /** Clone this agent, when the surrounding screen offers one (the console's
   *  header does; a guide step does not). */
  onClone?: (from: string) => void;
  /** A name the surrounding screen rejected on this agent's own Clone. */
  keyErrorMessage?: string | null;
  /** Per capability, the servers a capability reference stands for, as the
   *  API serves them (`CatalogEntry.capability_servers`). */
  capabilityServers?: CapabilityServers;
  /** The input slices a definition may name, as the API serves them
   *  (`CatalogEntry.data_source_choices`). */
  dataSourceChoices?: readonly string[];
  /** Every seeded definition key, as the API serves them
   *  (`CatalogEntry.builtin_agent_keys`). Absent from an older API: the five
   *  class built-ins are then the ones known. */
  builtinAgentKeys?: readonly string[] | null;
  /** The built-ins whose `enabled` switch the settings model refuses to
   *  change, as the API serves them (`CatalogEntry.always_enabled_agent_keys`). */
  alwaysEnabledAgentKeys?: readonly string[] | null;
}) {
  const agent = definitions[agentKey];
  const has = (section: AgentSection) => sections.includes(section);
  const showHeader = has("header");
  // Every seeded definition is built in: the settings model refuses an edit to
  // any of them but its `enabled` switch, so none is offered. The served list
  // names all of them; an API older than it leaves the five class built-ins.
  const locked = builtinKeySet(builtinAgentKeys).has(agentKey);

  const put = (key: string, next: Partial<AgentDefinitionEntry>) => {
    resolve.noteEdit(key, next);
    onChange(putEntry(definitions, key, next));
  };

  /** Removes an agent from the map. The header offers it only where `locked`
   *  is false: a built-in is re-seeded on the next load whether or not it is
   *  removed here. */
  const remove = (key: string) => onChange(removeEntry(definitions, key));

  const toggleRef = (key: string, ref: ToolRefEntry, on: boolean) => {
    const tools = definitions[key].tools;
    put(key, { tools: on ? [...tools, ref] : tools.filter((t) => !sameToolRef(t, ref)) });
  };

  const hasRef = (key: string, ref: ToolRefEntry) =>
    definitions[key].tools.some((t) => sameToolRef(t, ref));

  /** A server's whole box: ticked when the definition names it or holds a
   *  capability that reaches it, so a built-in shows the tools it resolves
   *  to. Unticking it takes both away, as unticking the server always did. */
  const toggleServer = (key: string, server: string, on: boolean) => {
    const tools = definitions[key].tools;
    put(key, {
      tools: on
        ? [...tools, { kind: "mcp", server, name: null }]
        : withoutServer(tools, server, capabilityServers),
    });
  };

  /** One `ask_<agent>` reference, in the shape the API stores it. */
  const askRef = (agent: string): ToolRefEntry => ({
    kind: "agent",
    server: null,
    name: null,
    agent,
  });

  /** The agents this one may be given as tools: every other analyst-role
   *  definition, whether or not it is enabled — a disabled one is refused at
   *  run time by name rather than silently missing from the list. Empty for a
   *  judge or a reporter, whose references the API always refuses, so the
   *  group is not offered where ticking a row is a guaranteed save error. */
  const askable = ASKABLE_ROLES.has(definitions[agentKey]?.role)
    ? Object.entries(definitions)
        .filter(([key, d]) => key !== agentKey && ASKABLE_ROLES.has(d.role))
        .map(([key]) => key)
    : [];

  /** The message the API put on one named field, so it can be rendered under
   *  that field rather than at the foot of the detail. */
  const fieldError = (field: string): string | undefined =>
    errors[`${entryKey}.${agentKey}.${field}`];

  if (!agent) return null;

  const result = resolve.result;
  const details = resolve.details;
  /** The entry-level message only: the field-level ones are rendered under
   *  the fields they name. */
  const entryError = errors[`${entryKey}.${agentKey}`];
  /** Models the last resolve reported, offered as suggestions on the model
   *  box — the override is still free text, since a provider may serve a
   *  model the probe did not list. */
  const probedModels =
    result && result !== "running" && result.models && result.models.length > 0
      ? result.models
      : null;

  const resolveButton = (
    <button
      type="button"
      className="text-xs text-accent-strong disabled:opacity-50"
      disabled={result === "running"}
      onClick={() => void resolve.resolve(agentKey)}
    >
      Resolve
    </button>
  );

  /* The verdict of the last press. It sits under the header in the console;
   * a guide step draws it in the Resolve section instead. */
  const status = (
    <>
      {result === "running" && <p className="text-[11px] text-text-muted">resolving…</p>}
      {result && result !== "running" && (
        <p
          className={`text-[11px] ${result.ok ? "text-status-green" : "text-status-red"}`}
          role="status"
        >
          {result.ok ? "ok" : "failed"} · {result.latency_ms} ms · {probeDetail(result.detail)}
          {details ? ` · prompt ${details.prompt_chars} chars` : ""}
        </p>
      )}
      {keyErrorMessage && (
        <p className="text-[11px] text-status-red" role="alert">
          {keyErrorMessage}
        </p>
      )}
      {entryError && (
        <p className="text-[11px] text-status-red" role="alert">
          {entryError}
        </p>
      )}
    </>
  );

  return (
    <section
      data-agent-detail={agentKey}
      aria-label={`Agent ${agentKey}`}
      className="min-w-0 border border-border rounded p-3 space-y-3"
    >
      {showHeader && (
        <>
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <span className="flex items-center gap-2 text-sm text-text-primary">
              <Bot size={16} aria-hidden="true" className="text-text-muted" />
              {agentDisplayName(agentKey, definitions)}
              {agentKeySuffix(agentKey, definitions) && (
                <span className="text-[11px] font-mono text-text-muted">
                  {agentKeySuffix(agentKey, definitions)}
                </span>
              )}
              {/* The role names what this agent is; where it is also the
                  key, the key beside it has already said so. */}
              {agent.role !== agentKey && (
                <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-bg-elevated text-text-muted">
                  {agent.role}
                </span>
              )}
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
                  aria-label={`${agentKey} enabled`}
                  disabled={(alwaysEnabledAgentKeys ?? []).includes(agentKey)}
                  checked={agent.enabled}
                  onChange={(e) => put(agentKey, { enabled: e.target.checked })}
                />
                enabled
              </label>
              {resolveButton}
              {/* There is one judge and one reporter and neither can be
                  cloned, so the detail that offers them offers no Clone. */}
              {agent.role !== "judge" && agent.role !== "report" && onClone && (
                <button
                  type="button"
                  className="text-xs text-accent-strong"
                  onClick={() => onClone(agentKey)}
                >
                  Clone
                </button>
              )}
              {/* A built-in has no Remove, and the switch beside this is
                  already how it is turned off. Two controls for one state,
                  worded in opposite directions, only raised the question of
                  whether they did the same thing. */}
              {!locked && (
                <button
                  type="button"
                  className="text-xs text-text-secondary"
                  onClick={() => remove(agentKey)}
                >
                  Remove
                </button>
              )}
            </div>
          </div>

          {status}
        </>
      )}

      {has("resolve") && (
        <div className="space-y-2">
          <div className="flex items-center gap-3">{resolveButton}</div>
          {status}
        </div>
      )}

      {has("identity") && (
        <fieldset className="border border-border rounded p-2">
          <legend className="text-xs text-text-muted px-1">Identity</legend>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
            <label className="block">
              <span className="text-text-muted">Label</span>
              <input
                className={input}
                aria-label={`${agentKey} label`}
                disabled={locked}
                value={agent.label}
                onChange={(e) => put(agentKey, { label: e.target.value })}
              />
              <FieldError message={fieldError("label")} />
            </label>
            {/* A built-in's role is what makes it that built-in, so only a
                custom definition may choose one. */}
            {!locked && (
              <label className="block">
                <span className="text-text-muted">Role</span>
                <select
                  className={input}
                  aria-label={`${agentKey} role`}
                  value={agent.role}
                  onChange={(e) =>
                    put(agentKey, { role: e.target.value as AgentDefinitionEntry["role"] })
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
                <FieldError message={fieldError("role")} />
              </label>
            )}
            {PROVIDER_ROLES.has(agent.role) && (
              <label className="block">
                <span className="text-text-muted">Static provider</span>
                <select
                  className={input}
                  aria-label={`${agentKey} static provider`}
                  disabled={locked}
                  value={agent.static_provider ?? ""}
                  onChange={(e) => put(agentKey, { static_provider: e.target.value || null })}
                >
                  <option value="">Inherit from settings</option>
                  {staticProviders.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
                <FieldError message={fieldError("static_provider")} />
              </label>
            )}
            {/* One loop's budget, on the card the agent is edited on rather
                than in a map keyed by agent name elsewhere in the settings:
                a lead that asks six specialists needs both raised, and a
                clone of it used to arrive with the tools and the default
                budget. Blank inherits the deployment's, and so does a reply
                from an API old enough not to carry the fields at all. */}
            <label className="block">
              <span className="text-text-muted">Steps per loop</span>
              <input
                type="number"
                min="1"
                step="1"
                className={input}
                aria-label={`${agentKey} max steps`}
                disabled={locked}
                placeholder="inherit"
                value={agent.max_steps == null ? "" : String(agent.max_steps)}
                onChange={(e) => put(agentKey, { max_steps: wholeNumber(e.target.value) })}
              />
              <FieldError message={fieldError("max_steps")} />
            </label>
            <label className="block">
              <span className="text-text-muted">Seconds per loop</span>
              <input
                type="number"
                min="1"
                step="1"
                className={input}
                aria-label={`${agentKey} timeout seconds`}
                disabled={locked}
                placeholder="inherit"
                value={agent.timeout_seconds == null ? "" : String(agent.timeout_seconds)}
                onChange={(e) => put(agentKey, { timeout_seconds: wholeNumber(e.target.value) })}
              />
              <FieldError message={fieldError("timeout_seconds")} />
            </label>
            {/* Where a section built from this agent's tool answers is drawn
                when the tool's kind places none; stored on each entry the
                agent writes, so a report renders without settings. */}
            <label className="block">
              <span className="text-text-muted">Console tab for its tools&apos; sections</span>
              <select
                className={input}
                aria-label={`${agentKey} tab`}
                disabled={locked}
                value={agent.tab ?? ""}
                onChange={(e) => put(agentKey, { tab: e.target.value || null })}
              >
                <option value="">none</option>
                {AGENT_TABS.map((tab) => (
                  <option key={tab} value={tab}>{tab}</option>
                ))}
              </select>
              <FieldError message={fieldError("tab")} />
            </label>
            {/* Whether the agent is asked for a technique id on each claim.
                Absent is on, which is what every definition written before
                the switch reads; off is stored as false and on as no field.
                Locked on a built-in, and fixed on a role that keeps its own
                claim format unless a stored off has to be put right. */}
            <label className="block sm:col-span-2">
              <span className="text-xs text-text-secondary flex items-center gap-1">
                <input
                  type="checkbox"
                  aria-label={`${agentKey} attck technique line`}
                  disabled={
                    locked ||
                    (!TECHNIQUE_LINE_ROLES.has(agent.role) && agent.attck_techniques !== false)
                  }
                  checked={agent.attck_techniques !== false}
                  onChange={(e) =>
                    onChange({
                      ...definitions,
                      [agentKey]: withTechniqueLine(agent, e.target.checked),
                    })
                  }
                />
                Ask for an ATT&amp;CK technique line on each claim
              </span>
              <span className="block text-[11px] text-text-muted mt-0.5">
                {TECHNIQUE_LINE_ROLES.has(agent.role)
                  ? "Turn off for an agent whose work is not malware behaviour. A technique line it writes anyway is still read and checked."
                  : "This role keeps its own claim format; only a generic or lead agent can turn the line off."}
              </span>
              <FieldError message={fieldError("attck_techniques")} />
            </label>
            {/* The slices of the job this agent is handed as its input text.
                None ticked is the role's own input, which is what every
                definition written before the field reads. A stored slice
                the served list does not hold is drawn, marked and kept. */}
            <div role="group" className="sm:col-span-2" aria-label={`${agentKey} input data`}>
              <span className="text-text-muted">Input data</span>
              <div className="flex gap-3 flex-wrap mt-0.5">
                {choiceRows(dataSourceChoices, agent.data_sources ?? []).map((row) => (
                  <label
                    key={row.key}
                    className="text-xs text-text-secondary flex items-center gap-1"
                  >
                    <input
                      type="checkbox"
                      aria-label={`${agentKey} input ${row.key}`}
                      disabled={locked}
                      checked={(agent.data_sources ?? []).includes(row.key)}
                      onChange={(e) =>
                        put(agentKey, {
                          data_sources: toggleChoice(
                            agent.data_sources ?? [],
                            row.key,
                            e.target.checked
                          ),
                        })
                      }
                    />
                    <span className="font-mono">{row.key}</span>
                    {!row.known && (
                      <span className="text-status-red">(not a source the API offers)</span>
                    )}
                  </label>
                ))}
              </div>
              {/* The sources are read in their stored order, the first at
                  the head of the input, so the order is shown. */}
              <span className="block text-[11px] text-text-muted mt-0.5">
                {(agent.data_sources ?? []).length === 0
                  ? "none ticked: the input its role reads"
                  : `read in this order: ${(agent.data_sources ?? []).join(", ")}`}
              </span>
              <FieldError message={fieldError("data_sources")} />
            </div>
          </div>
        </fieldset>
      )}

      {has("prompt") && (
        <fieldset className="border border-border rounded p-2">
          <legend className="text-xs text-text-muted px-1">
            {locked ? "Prompt (built in, read-only)" : "Prompt"}
          </legend>
          <div className="block text-xs">
            <textarea
              className={input}
              rows={locked ? 6 : 8}
              aria-label={`${agentKey} prompt`}
              disabled={locked}
              placeholder={agent.prompt === null ? "the built-in prompt for this role" : ""}
              value={
                locked
                  ? (details?.prompt ??
                    "press Resolve to see the built-in prompt this agent receives")
                  : (agent.prompt ?? "")
              }
              onChange={(e) => put(agentKey, { prompt: e.target.value })}
            />
            <FieldError message={fieldError("prompt")} />
          </div>
        </fieldset>
      )}

      {/* The LLM lives outside the definition (`llm.agents.<key>.*`), so
          the built-in lock never applies here — even a built-in role may
          run on a different model than the global default. */}
      {has("model") && (
        <ModelOverrideFields
          agentKey={agentKey}
          llmAgents={llmAgents}
          onChangeLlmAgents={onChangeLlmAgents}
          llmGlobal={llmGlobal}
          probedModels={probedModels}
          onEdited={resolve.clearProbe}
        />
      )}

      {/* The tool refs are a two-level thing — a server, and the tools
          under it — so they are drawn as one: a server node carries its
          "everything this server allows" box and, once its manifest has
          been listed, its own tools indented beneath it. */}
      {has("tools") && (
        <fieldset className="border border-border rounded p-2">
          <legend className="text-xs text-text-muted px-1">Tools</legend>
          <ul role="tree" aria-label={`${agentKey} tools`} className="space-y-1">
            {/* A built-in holding the reference is drawn with it, ticked and
                locked, as every other reference of a built-in is. */}
            {PROVIDER_ROLES.has(agent.role) &&
              agent.role !== "static" &&
              (!locked || hasRef(agentKey, { kind: "provider", server: null, name: null })) && (
              <li
                role="treeitem"
                aria-selected={hasRef(agentKey, {
                  kind: "provider",
                  server: null,
                  name: null,
                })}
              >
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${agentKey} provider tools`}
                    disabled={locked}
                    checked={hasRef(agentKey, { kind: "provider", server: null, name: null })}
                    onChange={(e) =>
                      toggleRef(
                        agentKey,
                        { kind: "provider", server: null, name: null },
                        e.target.checked
                      )
                    }
                  />
                  its static provider&rsquo;s tools
                </label>
              </li>
            )}
            {/* The job's sandbox report, read through in-process tools. Any
                role may hold it, a judge cross-checking a claim as much as a
                dynamic analyst. */}
            <li role="treeitem" aria-selected={hasRef(agentKey, SANDBOX_REF)}>
              <label className="text-xs text-text-secondary flex items-center gap-1">
                <input
                  type="checkbox"
                  aria-label={`${agentKey} sandbox tools`}
                  disabled={locked}
                  checked={hasRef(agentKey, SANDBOX_REF)}
                  onChange={(e) => toggleRef(agentKey, SANDBOX_REF, e.target.checked)}
                />
                the job&rsquo;s sandbox report tools
              </label>
            </li>
            {/* Delegation is a tool like any other, so it sits in the same
                tree: one row per agent this one may hand a task to. The row
                is titled by the tool's name because that is what the model
                reads in its toolbox. */}
            {askable.length > 0 && (
              <li role="treeitem" aria-expanded={true} aria-selected={false}>
                <span className="text-xs text-text-muted">Ask another agent</span>
                <ul role="group" className="ml-4 mt-1 space-y-0.5">
                  {askable.map((other) => (
                    <li key={other} role="treeitem" aria-selected={hasRef(agentKey, askRef(other))}>
                      <label className="text-xs text-text-secondary flex items-center gap-1">
                        <input
                          type="checkbox"
                          aria-label={`${agentKey} asks ${other}`}
                          disabled={locked}
                          checked={hasRef(agentKey, askRef(other))}
                          onChange={(e) => toggleRef(agentKey, askRef(other), e.target.checked)}
                        />
                        <span className="font-mono">ask_{other}</span>
                        <span className="text-text-muted">
                          {definitions[other].label || other}
                        </span>
                      </label>
                    </li>
                  ))}
                </ul>
              </li>
            )}
            {/* A capability reference names a kind of tool rather than a
                server: one row per capability, with the servers it stands for,
                so a clone can drop it as it drops a server. */}
            {offeredCapabilities(agent.tools, capabilityServers).map((cap) => (
              <li key={`capability:${cap}`} role="treeitem" aria-selected={hasRef(agentKey, capabilityRef(cap))}>
                <label className="text-xs text-text-secondary flex items-center gap-1">
                  <input
                    type="checkbox"
                    aria-label={`${agentKey} capability ${cap}`}
                    disabled={locked}
                    checked={hasRef(agentKey, capabilityRef(cap))}
                    onChange={(e) => toggleRef(agentKey, capabilityRef(cap), e.target.checked)}
                  />
                  <span>{cap} tools, by capability</span>
                  <span className="text-text-muted">
                    {(capabilityServers[cap] ?? []).length > 0
                      ? `(${(capabilityServers[cap] ?? []).join(", ")})`
                      : "(no server reached)"}
                  </span>
                </label>
              </li>
            ))}
            {Object.keys(servers).map((server) => {
              const listed = resolve.manifests[server];
              return (
                <li
                  key={server}
                  role="treeitem"
                  aria-expanded={listed && listed.length > 0 ? true : undefined}
                  aria-selected={holdsServer(agent.tools, server, capabilityServers)}
                >
                  <div className="flex items-center gap-2">
                    <label className="text-xs text-text-secondary flex items-center gap-1">
                      <input
                        type="checkbox"
                        aria-label={`${agentKey} server ${server}`}
                        disabled={locked}
                        checked={holdsServer(agent.tools, server, capabilityServers)}
                        onChange={(e) => toggleServer(agentKey, server, e.target.checked)}
                      />
                      {server} (all allowed tools)
                      {capabilitiesReaching(agent.tools, server, capabilityServers).map((cap) => (
                        <span key={cap} className="text-text-muted">
                          {" "}
                          by capability: {cap}
                        </span>
                      ))}
                    </label>
                    <button
                      type="button"
                      className="text-[11px] text-accent-strong"
                      onClick={() => void resolve.loadManifest(server, servers)}
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
                          aria-selected={hasRef(agentKey, { kind: "mcp", server, name: tool })}
                        >
                          <label className="text-xs text-text-secondary flex items-center gap-1">
                            <input
                              type="checkbox"
                              aria-label={`${agentKey} tool ${server}.${tool}`}
                              disabled={locked}
                              checked={hasRef(agentKey, { kind: "mcp", server, name: tool })}
                              onChange={(e) =>
                                toggleRef(
                                  agentKey,
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
                  {resolve.manifestErrors[server] !== undefined && (
                    <p className="ml-4 text-[11px] text-status-red" role="alert">
                      List tools failed: {resolve.manifestErrors[server]}
                    </p>
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
          <FieldError message={fieldError("tools")} />
        </fieldset>
      )}
    </section>
  );
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
 * whole server map: the PATCH body is the full dict, so the apply bar,
 * hidden-dirty count and reset behaviour need no special case, and a
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
  /** Stages the whole leaf. Built-ins arrive narrowed to what may be edited
   *  about them, which is what `stagedDefinitions` is for. */
  onChange: (value: StagedDefinitionMap) => void;
}) {
  /** What is stored right now, for the "changed" dot. An agent differs when
   *  either of the two leaves it spans has been edited: the definition itself,
   *  or its entry in the LLM override map. */
  const savedDefs = (current?.value ?? entry.default ?? {}) as Record<
    string,
    AgentDefinitionEntry
  >;
  /* What the editor draws is the stored map with the staged edits over it, not
   * the staged map itself: a built-in is staged as its role and its switch
   * alone (see `agentStaging`), which is not enough to draw a row with. */
  const builtins = builtinKeySet(entry.builtin_agent_keys);
  const value = displayedDefinitions(staged as StagedDefinitionMap | null, savedDefs, builtins);
  const stage = (next: Record<string, AgentDefinitionEntry>) =>
    onChange(stagedDefinitions(next, savedDefs, builtins));
  const llmAgents = (llmAgentsStaged ?? llmAgentsCurrent?.value ?? {}) as Record<
    string,
    AgentLLMOverride
  >;
  const savedLlm = (llmAgentsCurrent?.value ?? {}) as Record<string, AgentLLMOverride>;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<KeyError | null>(null);
  const newKeyRef = useRef<HTMLInputElement | null>(null);
  /** The agent the detail pane shows. Null until something is picked, and a
   *  key that has since been removed falls back to the first one. */
  const [picked, setPicked] = useState<string | null>(null);
  /** A role with no definition whose model entry the detail pane shows
   *  instead of an agent, or null. */
  const [pickedRole, setPickedRole] = useState<string | null>(null);
  const pick = (key: string) => {
    setPickedRole(null);
    setPicked(key);
  };

  const keys = Object.keys(value);
  const selected = picked !== null && picked in value ? picked : (keys[0] ?? null);
  const resolve = useAgentResolve(selected, value);

  const add = (from?: string) => {
    const at = from ?? ADD_BUTTON;
    // An empty name box on a Clone means "name it after its source"; on
    // Add it is still a name the operator has to supply.
    const typed = newKey.trim();
    const key = typed === "" && from ? copyKey(from, value) : typed;
    const problem = roleKeyError(key) ?? mapKeyError(key, value, "agent");
    if (problem) {
      setKeyError({ at, message: problem });
      newKeyRef.current?.focus();
      return;
    }
    setKeyError(null);
    setNewKey("");
    stage(cloneDefinition(value, key, from, resolve.probes[from ?? ""]));
    // A clone starts with the source's LLM override too, if it has one — the
    // override lives outside the definition, so cloning the definition alone
    // would silently drop it and leave the clone on the global default.
    if (from && llmAgents[from]) {
      onChangeLlmAgents({ ...llmAgents, [key]: { ...llmAgents[from] } });
    }
    // The new agent is what the operator wants to edit next, so the detail
    // pane follows it rather than staying on whatever was selected.
    pick(key);
  };

  /* The API qualifies an agent-map error with the
   * leaf it belongs to, and it points either at one field
   * (`core.agents.definitions.<key>.<field>`) or at the whole entry
   * (`core.agents.definitions.<key>`, for a name that is not a slug or an
   * entry that is not an object). Matching the field form alone left the
   * entry-level message with nothing to land on. */
  const anyErrorFor = (key: string): string | undefined =>
    Object.entries(errors).find(
      ([k]) => k === `${entry.key}.${key}` || k.startsWith(`${entry.key}.${key}.`)
    )?.[1];

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
            const itemResult = resolve.probes[key];
            const verdict =
              itemResult && itemResult !== "running" ? (itemResult.ok ? "ok" : "failed") : null;
            const changed =
              !deepEqual(item, savedDefs[key]) || !deepEqual(llmAgents[key], savedLlm[key]);
            return (
              <li
                key={key}
                role="option"
                data-agent={key}
                aria-selected={pickedRole === null && key === selected}
                tabIndex={pickedRole === null && key === selected ? 0 : -1}
                onClick={() => pick(key)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    pick(key);
                  }
                }}
                className={`px-2 py-1.5 cursor-pointer focus:outline-none focus:ring-1 focus:ring-accent ${
                  pickedRole === null && key === selected ? "bg-accent/10" : "hover:bg-bg-deep"
                }`}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <Dot
                    label={item.enabled ? "enabled" : "disabled"}
                    className={item.enabled ? "bg-status-green" : "bg-border"}
                  />
                  {/* The name an operator gave this analyst leads; its key
                      follows only where the two differ. */}
                  <span className="text-sm text-text-primary truncate">
                    {agentDisplayName(key, value)}
                  </span>
                  {changed && <Dot label="changed" className="bg-accent-strong" />}
                  {anyErrorFor(key) && <Dot label="invalid" className="bg-status-red" />}
                </div>
                <div className="flex items-center gap-2 text-[11px] text-text-muted pl-3.5">
                  {agentKeySuffix(key, value) && (
                    <span className="font-mono">{agentKeySuffix(key, value)}</span>
                  )}
                  {item.role !== key && <span>{item.role}</span>}
                  {builtins.has(key) && <span>built in</span>}
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

        {/* The two model-calling roles that are no definition: each is
            configured by an `llm.agents` entry under its own key, and with
            none runs on the global expert model. */}
        <p className="text-[11px] text-text-muted mt-3 mb-1">Roles with a model entry only</p>
        <ul
          role="listbox"
          aria-label="Roles with a model entry only"
          className="border border-border rounded divide-y divide-border"
        >
          {ROLE_ENTRIES.map((role) => (
            <li
              key={role.key}
              role="option"
              data-role={role.key}
              aria-selected={pickedRole === role.key}
              tabIndex={pickedRole === role.key ? 0 : -1}
              onClick={() => setPickedRole(role.key)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  setPickedRole(role.key);
                }
              }}
              className={`px-2 py-1.5 cursor-pointer focus:outline-none focus:ring-1 focus:ring-accent ${
                pickedRole === role.key ? "bg-accent/10" : "hover:bg-bg-deep"
              }`}
            >
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-sm text-text-primary truncate">{role.label}</span>
                {roleEntryChanged(role.key, llmAgents, savedLlm) && (
                  <Dot label="changed" className="bg-accent-strong" />
                )}
              </div>
              <div className="text-[11px] text-text-muted pl-0.5">
                <span className="font-mono">{role.key}</span>
                {" · "}
                {llmAgents[role.key]?.model
                  ? `${llmAgents[role.key].provider}/${llmAgents[role.key].model}`
                  : "global expert model"}
              </div>
            </li>
          ))}
        </ul>
      </div>

      {pickedRole !== null && (
        <RoleModelDetail
          key={`role-${pickedRole}`}
          role={ROLE_ENTRIES.find((role) => role.key === pickedRole)!}
          llmAgents={llmAgents}
          onChangeLlmAgents={onChangeLlmAgents}
          llmGlobal={llmGlobal}
        />
      )}

      {pickedRole === null && selected !== null && (
        <AgentDetail
          key={selected}
          agentKey={selected}
          definitions={value}
          onChange={stage}
          llmAgents={llmAgents}
          onChangeLlmAgents={onChangeLlmAgents}
          llmGlobal={llmGlobal}
          servers={servers}
          staticProviders={staticProviders}
          resolve={resolve}
          errors={errors}
          entryKey={entry.key}
          onClone={add}
          keyErrorMessage={keyError?.at === selected ? keyError.message : null}
          capabilityServers={entry.capability_servers ?? {}}
          builtinAgentKeys={entry.builtin_agent_keys}
          alwaysEnabledAgentKeys={entry.always_enabled_agent_keys}
          dataSourceChoices={entry.data_source_choices ?? []}
        />
      )}
    </div>
  );
}
