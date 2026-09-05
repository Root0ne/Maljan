"use client";

import type { CatalogEntry, McpServerEntry, SettingValue } from "@/types/settings";
import AgentDefinitionsEditor, {
  type AgentLLMOverride,
  type LlmGlobalFallback,
} from "./AgentDefinitionsEditor";
import ServerMapEditor from "./ServerMapEditor";
import { Widget } from "./widgets";

const APPLIES: Record<string, string> = {
  next_job: "next analysis",
  live: "immediately",
  restart: "restart required",
};

const SOURCE: Record<string, string> = { default: "default", env: "env", ui: "ui" };

export default function FieldRow({
  entry,
  current,
  staged,
  error,
  onChange,
  onUnstage,
  onReset,
  models,
  servers,
  staticProviders,
  llmAgentsCurrent,
  llmAgentsStaged,
  llmGlobal,
  onChangeLlmAgents,
}: {
  entry: CatalogEntry;
  current?: SettingValue;
  staged: unknown;
  error?: string;
  models?: string[];
  servers?: Record<string, McpServerEntry>;
  staticProviders?: string[];
  /** `core.llm.agents`'s own current/staged value, distinct from
   *  `current`/`staged` above which are this row's own entry: the
   *  agent-definitions editor stages that leaf as a whole, separately from
   *  `core.agents.definitions`. */
  llmAgentsCurrent?: SettingValue;
  llmAgentsStaged?: unknown;
  llmGlobal?: LlmGlobalFallback;
  onChangeLlmAgents?: (value: Record<string, AgentLLMOverride>) => void;
  onChange: (v: unknown) => void;
  onUnstage: () => void;
  onReset: () => void;
}) {
  const dirty = staged !== undefined;
  const source = current?.source ?? "default";
  const labelId = `setting-label-${entry.key}`;
  return (
    <div
      id={`setting-${entry.key}`}
      className={`grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] gap-2 sm:gap-4 py-3 border-b border-border ${
        dirty ? "bg-accent/5" : ""
      }`}
    >
      <div>
        <div className="flex items-center gap-2 flex-wrap">
          <span id={labelId} className="text-sm text-text-primary">
            {entry.title}
          </span>
          <span
            className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded ${
              source === "ui"
                ? "bg-accent/20 text-accent-strong"
                : source === "env"
                  ? "bg-status-orange/10 text-status-orange"
                  : "bg-border text-text-muted"
            }`}
          >
            {SOURCE[source]}
          </span>
          <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-border text-text-muted">
            {APPLIES[entry.applies]}
          </span>
          {dirty && (
            <span className="text-[10px] uppercase tracking-wider text-accent-strong">
              modified
            </span>
          )}
        </div>
        <button
          type="button"
          className="text-[11px] font-mono text-text-muted hover:text-text-secondary break-all"
          title="Copy key"
          onClick={() => void navigator.clipboard?.writeText(entry.key)}
        >
          {entry.key}
        </button>
        <p className="text-xs text-text-secondary mt-1">{entry.description}</p>
        {!entry.editable && entry.reason && (
          <p className="text-[11px] text-text-muted mt-1">{entry.reason}</p>
        )}
      </div>
      <div>
        <div role="group" aria-labelledby={labelId}>
          {entry.editor === "server_map" ? (
            <ServerMapEditor
              entry={entry}
              current={current}
              staged={staged}
              onChange={onChange}
            />
          ) : entry.editor === "agent_definitions" ? (
            <AgentDefinitionsEditor
              entry={entry}
              current={current}
              staged={staged}
              servers={servers ?? {}}
              staticProviders={staticProviders ?? []}
              llmAgentsCurrent={llmAgentsCurrent}
              llmAgentsStaged={llmAgentsStaged}
              llmGlobal={llmGlobal ?? { providerChoices: null, providerValue: null, modelValue: null }}
              onChangeLlmAgents={onChangeLlmAgents ?? (() => undefined)}
              onChange={onChange}
            />
          ) : (
            <Widget
              entry={entry}
              current={current}
              staged={staged}
              onChange={onChange}
              onUnstage={onUnstage}
              models={models}
            />
          )}
        </div>
        {error && (
          <div className="text-[11px] text-status-red mt-1" role="alert">
            {error}
          </div>
        )}
        <div className="flex gap-3 mt-1">
          {dirty && (
            <button type="button" className="text-[11px] text-text-secondary" onClick={onUnstage}>
              Discard change
            </button>
          )}
          {source === "ui" && entry.editable && (
            <button type="button" className="text-[11px] text-text-secondary" onClick={onReset}>
              Reset to env
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
