"use client";

import { useEffect, useState } from "react";
import type {
  AgentDefinitionEntry,
  CatalogEntry,
  McpServerEntry,
  SettingValue,
} from "@/types/settings";
import AgentDefinitionsEditor, {
  type AgentLLMOverride,
  type LlmGlobalFallback,
} from "./AgentDefinitionsEditor";
import ProfilesEditor from "./ProfilesEditor";
import ServerMapEditor from "./ServerMapEditor";
import { APPLIES_LABEL } from "./vocabulary";
import { Widget } from "./widgets";

const SOURCE: Record<string, string> = { default: "default", env: "env", ui: "ui" };

/** Types whose control is short enough to sit beside the title. Everything
 *  else — lists, JSON, and every composite editor — drops below it. */
const NARROW_TYPES = new Set(["bool", "int", "float", "enum", "str", "secret"]);

/** How long a description may be before it is folded to its first sentence. */
const DESCRIPTION_LIMIT = 140;

function firstSentence(text: string): string {
  const m = /^.*?[.!?](?=\s|$)/.exec(text);
  return m ? m[0] : text;
}

/** The key, as a button that copies it. The key text stays visible either way
 *  — the feedback is a separate word beside it, never a replacement. */
function CopyKeyButton({ settingKey }: { settingKey: string }) {
  const [feedback, setFeedback] = useState<string | null>(null);

  useEffect(() => {
    if (!feedback) return;
    const t = setTimeout(() => setFeedback(null), 2000);
    return () => clearTimeout(t);
  }, [feedback]);

  return (
    <>
      <button
        type="button"
        className="text-[11px] font-mono text-text-muted hover:text-text-secondary break-all"
        title="Copy key"
        onClick={async () => {
          try {
            const clipboard = navigator.clipboard;
            if (!clipboard) throw new Error("no clipboard");
            await clipboard.writeText(settingKey);
            setFeedback("Copied");
          } catch {
            setFeedback("Copy unavailable");
          }
        }}
      >
        {settingKey}
      </button>
      {feedback && (
        <span className="text-[10px] text-text-muted" role="status">
          {feedback}
        </span>
      )}
    </>
  );
}

function Description({ text, full }: { text: string; full: boolean }) {
  const [expanded, setExpanded] = useState(false);
  if (!text) return null;
  const head = firstSentence(text);
  // A "more" toggle only earns its place when there is actually more behind
  // it: a description with no sentence-ending punctuation before the limit
  // has `firstSentence` fall back to the whole text, and a toggle that reveals
  // nothing new is worse than none.
  const foldable = !full && text.length > DESCRIPTION_LIMIT && head.length < text.length;
  if (!foldable) {
    return <p className="text-xs text-text-secondary mt-1">{text}</p>;
  }
  return (
    <p className="text-xs text-text-secondary mt-1">
      {expanded ? text : head}{" "}
      <button
        type="button"
        aria-expanded={expanded}
        className="text-[11px] text-accent-strong"
        onClick={() => setExpanded((v) => !v)}
      >
        {expanded ? "less" : "more"}
      </button>
    </p>
  );
}

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
  definitions,
  activeProfile,
  onSetActive,
  errors,
  variant = "console",
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
  /** `core.agents.definitions`'s effective value, read-only here — the
   *  profiles editor only offers enabled, non-judge definitions. */
  definitions?: Record<string, AgentDefinitionEntry>;
  /** `core.agents.profile`'s effective value, for the "active" badge. */
  activeProfile?: string;
  /** Stages `core.agents.profile` — a "Set active" click, distinct from this
   *  row's own `onChange` which stages `core.agents.profiles`. */
  onSetActive?: (name: string) => void;
  onChange: (v: unknown) => void;
  onUnstage: () => void;
  onReset: () => void;
  /** The full validation-error map, keyed by dotted path — not just this
   *  row's own key — so the agent-definitions and profiles editors can find a
   *  qualified error like `core.agents.definitions.<key>.prompt` or
   *  `core.agents.profiles.<key>` and land it on the card that caused it
   *  rather than a leaf-wide banner. */
  errors?: Record<string, string>;
  /** `console` is the settings page's compact row. `guide` is the setup
   *  guides' step field: no key/meta line, the whole description, and no
   *  Discard/Remove links — a guide step owns those decisions itself. */
  variant?: "console" | "guide";
}) {
  const dirty = staged !== undefined;
  const source = current?.source ?? "default";
  const labelId = `setting-label-${entry.key}`;
  /* B7 (dev audit 2026-09-06): the controls on this tab carried neither an id
   * nor a name, so nothing could associate the title with the input it names
   * except the widget's own `aria-label`. A composite editor renders many
   * controls and has no single one to point at, so it keeps the labelled
   * group below and the title stays a span there. */
  const inputId = `setting-input-${entry.key}`;
  const single = entry.editor === null;
  const guide = variant === "guide";
  const sideBySide = !guide && single && NARROW_TYPES.has(entry.type);

  const control = (
    <>
      <div role="group" aria-labelledby={labelId}>
        {entry.editor === "server_map" ? (
          <ServerMapEditor
            entry={entry}
            current={current}
            staged={staged}
            errors={errors ?? {}}
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
            errors={errors ?? {}}
            onChange={onChange}
          />
        ) : entry.editor === "profiles" ? (
          <ProfilesEditor
            entry={entry}
            current={current}
            staged={staged}
            definitions={definitions ?? {}}
            activeProfile={activeProfile ?? "default"}
            errors={errors ?? {}}
            onChange={onChange}
            onSetActive={onSetActive ?? (() => undefined)}
          />
        ) : (
          <Widget
            entry={entry}
            current={current}
            staged={staged}
            onChange={onChange}
            onUnstage={onUnstage}
            models={models}
            inputId={inputId}
          />
        )}
      </div>
      {error && (
        <div className="text-[11px] text-status-red mt-1" role="alert">
          {error}
        </div>
      )}
      {!guide && (
        <div className="flex gap-3 mt-1">
          {dirty && (
            <button type="button" className="text-[11px] text-text-secondary" onClick={onUnstage}>
              Discard
            </button>
          )}
          {source === "ui" && entry.editable && (
            <button
              type="button"
              className="text-[11px] text-text-secondary"
              title="Removes the stored value now, without Apply"
              onClick={onReset}
            >
              Remove override
            </button>
          )}
        </div>
      )}
    </>
  );

  const heading = (
    <>
      {single ? (
        <label id={labelId} htmlFor={inputId} className="text-sm text-text-primary">
          {entry.title}
        </label>
      ) : (
        <span id={labelId} className="text-sm text-text-primary">
          {entry.title}
        </span>
      )}
      {!guide && (
        <div className="flex items-center gap-2 flex-wrap mt-0.5">
          <CopyKeyButton settingKey={entry.key} />
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
            {APPLIES_LABEL[entry.applies]}
          </span>
          {dirty && (
            <span className="text-[10px] uppercase tracking-wider text-accent-strong">modified</span>
          )}
        </div>
      )}
      <Description text={entry.description} full={guide} />
      {!entry.editable && entry.reason && (
        <p className="text-[11px] text-text-muted mt-1">{entry.reason}</p>
      )}
    </>
  );

  return (
    <div
      id={`setting-${entry.key}`}
      className={`${
        sideBySide
          ? "grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] gap-2 md:gap-4 items-start"
          : ""
      } py-3 border-b border-border ${dirty ? "bg-accent/5" : ""}`}
    >
      <div className="min-w-0">{heading}</div>
      <div className={sideBySide ? "min-w-0" : "min-w-0 mt-2"}>{control}</div>
    </div>
  );
}
