"use client";

import { useEffect, useState } from "react";
import type { AgentDefinitionEntry } from "@/types/settings";
import {
  AgentDetail,
  BUILTIN_AGENT_KEYS,
  cloneDefinition,
  useAgentResolve,
  type AgentLLMOverride,
} from "../../configuration/AgentDefinitionsEditor";
import { buildFieldRowProps } from "../../configuration/fieldRowProps";
import { copyKey, mapKeyError } from "../../configuration/mapEditorHelpers";
import { useSettingsContext } from "../../configuration/SettingsContext";
import { stateString, type GuideStepProps } from "./types";

const DEFINITIONS_KEY = "core.agents.definitions";
const LLM_AGENTS_KEY = "core.llm.agents";
/** The radio value for "not a clone". */
const BLANK = " blank";
/** Spec §3.1: there is one judge and it is a built-in, so it is not on offer
 *  as a starting point. */
const CLONEABLE = ["static", "dynamic", "network"];

export const AGENT_STEP_SECTIONS = [
  "identity",
  "prompt",
  "model",
  "tools",
  "resolve",
] as const;
export type AgentStepSection = (typeof AGENT_STEP_SECTIONS)[number];

/** The section a guide step asked for, or the first one when it named
 *  nothing this component draws. */
export function agentStepSection(section: string | undefined): AgentStepSection {
  return (AGENT_STEP_SECTIONS as readonly string[]).includes(section ?? "")
    ? (section as AgentStepSection)
    : "identity";
}

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/**
 * One section of the console's agent form, for the analyst this guide is
 * creating.
 *
 * Until `state.agentKey` names one, this is the "Start from" chooser: clone a
 * built-in, or start from a blank generic agent, under the same key rules and
 * the same clone semantics (`cloneDefinition`) the console's Add and Clone
 * buttons use — including the LLM override, which lives on its own leaf and
 * would otherwise be silently dropped by a clone. After that it is
 * `AgentDetail`, staging the same two leaves through the same two callbacks.
 *
 * The `resolve` section records its verdict in `state.resolvedOk` so the
 * guide can block Continue until the definition actually resolves.
 */
export default function AgentFormStep({
  section,
  state,
  setState,
}: GuideStepProps & { section: AgentStepSection }) {
  const ctx = useSettingsContext();
  const entry = ctx.entriesByKey[DEFINITIONS_KEY];
  const definitions = (ctx.pending[DEFINITIONS_KEY] ??
    ctx.values[DEFINITIONS_KEY]?.value ??
    entry?.default ??
    {}) as Record<string, AgentDefinitionEntry>;
  const llmAgents = (ctx.pending[LLM_AGENTS_KEY] ??
    ctx.values[LLM_AGENTS_KEY]?.value ??
    {}) as Record<string, AgentLLMOverride>;

  const chosen = stateString(state, "agentKey");
  const agentKey = chosen !== null && chosen in definitions ? chosen : null;
  const resolve = useAgentResolve(agentKey, definitions);

  const [from, setFrom] = useState<string>(BLANK);
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);

  const result = resolve.result;
  const resolvedOk = result !== undefined && result !== "running" && result.ok;
  useEffect(() => {
    if (state.resolvedOk === resolvedOk) return;
    // The guide's `canContinue` for the Resolve step reads this; it is the
    // verdict of a request, so there is nothing to derive it from at render.
    setState({ resolvedOk });
  }, [resolvedOk, state.resolvedOk, setState]);

  if (!entry) {
    return <p role="alert">The agent definitions are not in the catalog.</p>;
  }

  const create = () => {
    const source = from === BLANK ? undefined : from;
    // The same rule the console applies: an empty name box on a clone means
    // "name it after its source"; on a blank agent it is a name the operator
    // has to supply.
    const typed = newKey.trim();
    const key = typed === "" && source ? copyKey(source, definitions) : typed;
    const problem = mapKeyError(key, definitions, "agent");
    if (problem) {
      setKeyError(problem);
      return;
    }
    setKeyError(null);
    ctx.stage(
      DEFINITIONS_KEY,
      cloneDefinition(definitions, key, source, source ? resolve.probes[source] : undefined)
    );
    if (source && llmAgents[source]) {
      ctx.stage(LLM_AGENTS_KEY, { ...llmAgents, [key]: { ...llmAgents[source] } });
    }
    setState({ agentKey: key, resolvedOk: false });
  };

  if (agentKey === null) {
    const builtins = CLONEABLE.filter(
      (key) => key in definitions && BUILTIN_AGENT_KEYS.has(key)
    );
    return (
      <fieldset className="border-0 p-0 m-0" data-testid="agent-chooser">
        <legend className="sr-only">Start from</legend>
        <div className="space-y-2">
          <label className="flex gap-2 items-center text-sm text-text-primary">
            <input
              type="radio"
              name="guide-agent-source"
              value="clone"
              checked={from !== BLANK}
              onChange={() => setFrom(builtins[0] ?? BLANK)}
              disabled={builtins.length === 0}
            />
            Clone a built-in
          </label>
          <select
            className={input}
            aria-label="built-in to clone"
            disabled={builtins.length === 0}
            value={from === BLANK ? "" : from}
            onChange={(e) => setFrom(e.target.value || BLANK)}
          >
            <option value="">choose a built-in</option>
            {builtins.map((key) => (
              <option key={key} value={key}>
                {key}
              </option>
            ))}
          </select>
          <label className="flex gap-2 items-center text-sm text-text-primary">
            <input
              type="radio"
              name="guide-agent-source"
              value={BLANK}
              checked={from === BLANK}
              onChange={() => setFrom(BLANK)}
            />
            Blank generic agent
          </label>
          <input
            className={input}
            placeholder="new agent name"
            aria-label="new agent name"
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
          />
        </div>
        <div className="flex items-center gap-3 mt-2">
          <button type="button" className="text-xs text-accent-strong" onClick={create}>
            Create the analyst
          </button>
          {keyError && (
            <span className="text-[11px] text-status-red" role="alert">
              {keyError}
            </span>
          )}
        </div>
      </fieldset>
    );
  }

  const props = buildFieldRowProps(ctx, entry);

  return (
    <div>
      <p className="text-xs text-text-secondary mb-2">
        Editing <span className="font-mono text-text-primary">{agentKey}</span>{" "}
        <button
          type="button"
          className="text-[11px] text-accent-strong"
          onClick={() => setState({ agentKey: null, resolvedOk: false })}
        >
          Start from something else
        </button>
      </p>
      <AgentDetail
        agentKey={agentKey}
        definitions={definitions}
        onChange={(v) => ctx.stage(DEFINITIONS_KEY, v)}
        llmAgents={llmAgents}
        onChangeLlmAgents={props.onChangeLlmAgents}
        llmGlobal={props.llmGlobal}
        servers={props.servers}
        staticProviders={props.staticProviders}
        resolve={resolve}
        errors={ctx.errors}
        entryKey={DEFINITIONS_KEY}
        sections={[section]}
      />
    </div>
  );
}
