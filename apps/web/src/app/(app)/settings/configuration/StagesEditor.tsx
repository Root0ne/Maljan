"use client";

import { useRef, useState } from "react";
import type {
  AgentDefinitionEntry,
  CatalogEntry,
  ProfileEntry,
  SettingValue,
  StageEntry,
  StageKind,
} from "@/types/settings";
import {
  ADD_BUTTON,
  copyKey,
  mapKeyError,
  putEntry,
  removeEntry,
  type KeyError,
} from "./mapEditorHelpers";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/** Seeded by the settings model, so they lock rather than delete. */
const BUILTIN_PROFILES = new Set(["default", "measurement"]);

const KINDS: StageKind[] = ["analysis", "debate", "verdict", "report"];

/** What each stage kind is for, in one line, under the selector. */
const KIND_HELP: Record<StageKind, string> = {
  analysis: "Runs the agents it names, on the data they are configured to read.",
  debate: "Argues over the analysis stages upstream of it until they agree or the rounds run out.",
  verdict: "Runs the judge over everything the stages before it produced.",
  report: "Builds the final report. It is always the last stage.",
};

const blankStage = (key: string): StageEntry => ({
  key,
  label: "",
  kind: "analysis",
  agents: [],
  depends_on: [],
  when: "",
  mode: "sequential",
  inject_upstream: "findings",
  debate: null,
  builtin_tools: true,
});

/**
 * The whole `core.agents.profiles` leaf: one card per team, one card per stage.
 *
 * The stage list is ordered and the order is meaningful twice over. It is the
 * run order, and it is also what makes a dependency legal: a stage may only
 * depend on a stage above it, which is how a cycle is made unrepresentable
 * rather than merely detectable. Moving a stage up past something it depends
 * on is therefore refused here rather than sent to the API to be rejected.
 *
 * Conditions are not validated in the browser. The grammar lives in
 * `pipeline/conditions.py` and the API answers with a per-stage error keyed
 * `core.agents.profiles.<team>.stages.<stage>.when`, which lands under the box
 * the operator typed it into — one grammar, one answer.
 */
export default function StagesEditor({
  entry,
  current,
  staged,
  definitions,
  activeProfile,
  errors,
  onChange,
  onSetActive,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  definitions: Record<string, AgentDefinitionEntry>;
  activeProfile: string;
  /** Validation errors from the last failed apply, keyed by the server's full
   *  dotted path (`core.agents.profiles.<team>` or
   *  `core.agents.profiles.<team>.stages.<stage>.<field>`), so a rejected
   *  stage is named on its own card rather than in a leaf-wide banner. */
  errors: Record<string, string>;
  onChange: (value: Record<string, ProfileEntry>) => void;
  onSetActive: (name: string) => void;
}) {
  const value = (staged ?? current?.value ?? entry.default ?? {}) as Record<string, ProfileEntry>;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<KeyError | null>(null);
  const newKeyRef = useRef<HTMLInputElement | null>(null);

  const analysts = Object.entries(definitions)
    .filter(([, d]) => d.enabled && d.role !== "judge" && d.role !== "report")
    .map(([k]) => k);

  const put = (key: string, next: Partial<ProfileEntry>) => onChange(putEntry(value, key, next));

  /**
   * A stage edit, which also stops the API deriving this team's stages.
   *
   * A team the migration converted still carries `derived_from_analysts`, and
   * while it does the settings model rebuilds its stages from the analyst list
   * and the two global keys on every load — which is what keeps an untouched
   * team following `llm.parallel_analysts`. The moment an operator changes a
   * stage the stages are theirs, and leaving the flag set would throw the edit
   * away on the next read.
   */
  const putStages = (profile: string, stages: StageEntry[]) =>
    put(profile, { stages, derived_from_analysts: false });

  const putStage = (profile: string, index: number, next: Partial<StageEntry>) => {
    const stages = [...value[profile].stages];
    stages[index] = { ...stages[index], ...next };
    putStages(profile, stages);
  };

  const moveStage = (profile: string, index: number, by: number) => {
    const stages = [...value[profile].stages];
    const target = index + by;
    if (target < 0 || target >= stages.length) return;
    [stages[index], stages[target]] = [stages[target], stages[index]];
    // A move that would put a stage above something it depends on is dropped
    // rather than sent: the dependency would be illegal the moment it landed,
    // and an editor that stages an impossible team is worse than one that
    // declines the keystroke.
    const seen = new Set<string>();
    for (const stage of stages) {
      if (stage.depends_on.some((d) => !seen.has(d))) return;
      seen.add(stage.key);
    }
    putStages(profile, stages);
  };

  const addStage = (profile: string) => {
    const stages = value[profile].stages;
    const used = new Set(stages.map((s) => s.key));
    let n = stages.length + 1;
    while (used.has(`stage_${n}`)) n += 1;
    const previous = stages.length ? [stages[stages.length - 1].key] : [];
    // A report stage is always last, so a new stage goes in front of it.
    const reportIndex = stages.findIndex((s) => s.kind === "report");
    const fresh = { ...blankStage(`stage_${n}`), depends_on: previous };
    const next =
      reportIndex === -1
        ? [...stages, fresh]
        : [
            ...stages.slice(0, reportIndex),
            { ...fresh, depends_on: stages[reportIndex].depends_on },
            { ...stages[reportIndex], depends_on: [fresh.key] },
          ];
    putStages(profile, next);
  };

  const removeStage = (profile: string, index: number) => {
    const stages = value[profile].stages;
    const gone = stages[index].key;
    putStages(
      profile,
      stages
        .filter((_, i) => i !== index)
        .map((s) => ({ ...s, depends_on: s.depends_on.filter((d) => d !== gone) }))
    );
  };

  const add = (from?: string) => {
    const at = from ?? ADD_BUTTON;
    // Cloning with an empty name box names the copy after its source rather
    // than silently doing nothing.
    const typed = newKey.trim();
    const key = typed === "" && from ? copyKey(from, value) : typed;
    const problem = mapKeyError(key, value, "team");
    if (problem) {
      setKeyError({ at, message: problem });
      newKeyRef.current?.focus();
      return;
    }
    setKeyError(null);
    setNewKey("");
    const source = from ? value[from] : undefined;
    onChange({
      ...value,
      [key]: source
        ? {
            ...source,
            label: source.label ? `${source.label} (copy)` : key,
            stages: source.stages.map((s) => ({ ...s, depends_on: [...s.depends_on] })),
            analysts: [...source.analysts],
            derived_from_analysts: false,
          }
        : { label: "", stages: [], analysts: [], derived_from_analysts: false },
    });
  };

  /** The message for exactly ``path``, or for something under it.
   *
   *  ``exact`` is what the team card asks for: a stage's own error is keyed
   *  under the team, so a prefix match would render a stage's condition error
   *  a second time in the team-wide banner above it. */
  const errorFor = (path: string, exact = false) =>
    Object.entries(errors).find(([k]) => (exact ? k === path : k === path || k.startsWith(`${path}.`)))?.[1];

  return (
    <div className="space-y-3" data-testid="stages-editor">
      {Object.entries(value).map(([key, profile]) => {
        const locked = BUILTIN_PROFILES.has(key);
        const stages = profile.stages ?? [];
        const cardError = errorFor(`${entry.key}.${key}`, true);
        return (
          <div key={key} className="border border-border rounded p-3" data-profile={key}>
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-sm text-text-primary font-mono">
                {key}
                {key === activeProfile && (
                  <span className="ml-2 text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-accent/20 text-accent-strong">
                    active
                  </span>
                )}
                {locked && (
                  <span className="ml-2 text-[10px] uppercase tracking-wider text-text-muted">
                    built in
                  </span>
                )}
              </span>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  className="text-xs text-accent-strong disabled:opacity-60"
                  aria-pressed={key === activeProfile}
                  disabled={key === activeProfile}
                  onClick={() => {
                    if (key !== activeProfile) onSetActive(key);
                  }}
                >
                  Set active
                </button>
                <button type="button" className="text-xs text-accent-strong" onClick={() => add(key)}>
                  Clone
                </button>
                {!locked && (
                  <button
                    type="button"
                    className="text-xs text-text-secondary"
                    onClick={() => onChange(removeEntry(value, key))}
                  >
                    Remove
                  </button>
                )}
              </div>
            </div>

            <label className="block text-xs">
              <span className="text-text-muted">Label</span>
              <input
                className={input}
                aria-label={`${key} label`}
                disabled={locked}
                value={profile.label}
                onChange={(e) => put(key, { label: e.target.value })}
              />
            </label>

            <ol className="mt-3 space-y-2">
              {stages.map((stage, index) => (
                <StageCard
                  key={stage.key}
                  profile={key}
                  stage={stage}
                  index={index}
                  total={stages.length}
                  earlier={stages.slice(0, index).map((s) => s.key)}
                  analysts={analysts}
                  locked={locked}
                  error={errorFor(`${entry.key}.${key}.stages.${stage.key}`)}
                  onPatch={(next) => putStage(key, index, next)}
                  onMove={(by) => moveStage(key, index, by)}
                  onRemove={() => removeStage(key, index)}
                />
              ))}
              {stages.length === 0 && (
                <li className="text-[11px] text-status-red" role="alert">
                  a team needs at least one stage
                </li>
              )}
            </ol>

            {cardError && (
              <p className="text-[11px] text-status-red mt-2" role="alert">
                {cardError}
              </p>
            )}
            {keyError?.at === key && (
              <p className="text-[11px] text-status-red mt-2 text-right" role="alert">
                {keyError.message}
              </p>
            )}

            {!locked && (
              <button
                type="button"
                className="text-xs text-accent-strong mt-2"
                onClick={() => addStage(key)}
              >
                Add stage
              </button>
            )}
          </div>
        );
      })}

      <div className="flex items-center gap-2">
        <input
          className={input}
          ref={newKeyRef}
          placeholder="new team name"
          aria-label="new team name"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
        />
        <button type="button" className="text-xs text-accent-strong" onClick={() => add()}>
          Add team
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

function StageCard({
  profile,
  stage,
  index,
  total,
  earlier,
  analysts,
  locked,
  error,
  onPatch,
  onMove,
  onRemove,
}: {
  profile: string;
  stage: StageEntry;
  index: number;
  total: number;
  earlier: string[];
  analysts: string[];
  locked: boolean;
  error: string | undefined;
  onPatch: (next: Partial<StageEntry>) => void;
  onMove: (by: number) => void;
  onRemove: () => void;
}) {
  // A built-in team's stages are the paper's architecture and stay fixed, with
  // the two exceptions the settings model also allows: the debate options and
  // the built-in tool switch. Everything else on the card is read-only there.
  const fixed = locked;
  const debate = stage.debate;
  const unused = analysts.filter((a) => !stage.agents.includes(a));
  const label = `${profile} ${stage.key}`;

  return (
    <li className="border border-border rounded p-2" data-stage={stage.key}>
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-mono text-text-primary">
          {index + 1}. {stage.key}
          <span className="ml-2 text-[10px] uppercase tracking-wider text-text-muted">
            {stage.kind}
          </span>
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="text-sm text-text-secondary disabled:opacity-40"
            aria-label={`Move ${stage.key} up`}
            disabled={fixed || index === 0}
            onClick={() => onMove(-1)}
          >
            ↑
          </button>
          <button
            type="button"
            className="text-sm text-text-secondary disabled:opacity-40"
            aria-label={`Move ${stage.key} down`}
            disabled={fixed || index === total - 1}
            onClick={() => onMove(1)}
          >
            ↓
          </button>
          <button
            type="button"
            className="text-[11px] text-text-secondary disabled:opacity-40"
            aria-label={`Remove stage ${stage.key}`}
            disabled={fixed}
            onClick={onRemove}
          >
            Remove stage
          </button>
        </div>
      </div>

      <div className="grid gap-2 sm:grid-cols-2 mt-2">
        <label className="block text-xs">
          <span className="text-text-muted">Key</span>
          <input
            className={input}
            aria-label={`${label} key`}
            disabled={fixed}
            value={stage.key}
            onChange={(e) => onPatch({ key: e.target.value })}
          />
        </label>
        <label className="block text-xs">
          <span className="text-text-muted">Kind</span>
          <select
            className={input}
            aria-label={`${label} kind`}
            disabled={fixed}
            value={stage.kind}
            onChange={(e) => onPatch({ kind: e.target.value as StageKind })}
          >
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </select>
          <span className="text-[10px] text-text-muted">{KIND_HELP[stage.kind]}</span>
        </label>
      </div>

      {stage.kind === "analysis" && (
        <>
          <ul className="mt-2 space-y-1">
            {stage.agents.map((agent) => (
              <li key={agent} className="flex items-center gap-2 text-xs">
                <span className="font-mono text-text-primary">{agent}</span>
                <button
                  type="button"
                  className="text-[11px] text-text-secondary disabled:opacity-40"
                  aria-label={`Remove agent ${agent} from ${stage.key}`}
                  disabled={fixed}
                  onClick={() => onPatch({ agents: stage.agents.filter((a) => a !== agent) })}
                >
                  Remove agent
                </button>
              </li>
            ))}
            {stage.agents.length === 0 && (
              <li className="text-[11px] text-status-red" role="alert">
                an analysis stage needs at least one agent
              </li>
            )}
          </ul>
          {!fixed && unused.length > 0 && (
            <label className="block text-xs mt-1">
              <span className="text-text-muted">Add agent</span>
              <select
                className={input}
                aria-label={`${label} add agent`}
                value=""
                onChange={(e) =>
                  e.target.value && onPatch({ agents: [...stage.agents, e.target.value] })
                }
              >
                <option value="">choose an enabled agent</option>
                {unused.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </label>
          )}
          <label className="block text-xs mt-1">
            <span className="text-text-muted">Run mode</span>
            <select
              className={input}
              aria-label={`${label} mode`}
              disabled={fixed}
              value={stage.mode}
              onChange={(e) => onPatch({ mode: e.target.value as StageEntry["mode"] })}
            >
              <option value="sequential">sequential</option>
              <option value="parallel">parallel</option>
            </select>
          </label>
        </>
      )}

      {earlier.length > 0 && (
        <fieldset className="mt-2 text-xs">
          <legend className="text-text-muted">Depends on</legend>
          {earlier.map((candidate) => (
            <label key={candidate} className="mr-3 inline-flex items-center gap-1">
              <input
                type="checkbox"
                aria-label={`${label} depends on ${candidate}`}
                disabled={fixed}
                checked={stage.depends_on.includes(candidate)}
                onChange={(e) =>
                  onPatch({
                    depends_on: e.target.checked
                      ? [...stage.depends_on, candidate]
                      : stage.depends_on.filter((d) => d !== candidate),
                  })
                }
              />
              <span className="font-mono">{candidate}</span>
            </label>
          ))}
        </fieldset>
      )}

      <label className="block text-xs mt-2">
        <span className="text-text-muted">Runs when</span>
        <input
          className={input}
          aria-label={`${label} condition`}
          placeholder="always"
          disabled={fixed}
          value={stage.when}
          onChange={(e) => onPatch({ when: e.target.value })}
        />
        <span className="text-[10px] text-text-muted">
          Empty means always. Otherwise an expression over the sample and the stages before it,
          such as <code>platform == &quot;windows&quot;</code> or{" "}
          <code>stages.triage.claim_count &gt; 0</code>.
        </span>
      </label>

      <div className="grid gap-2 sm:grid-cols-2 mt-2">
        <label className="block text-xs">
          <span className="text-text-muted">Upstream findings</span>
          <select
            className={input}
            aria-label={`${label} upstream`}
            disabled={fixed}
            value={stage.inject_upstream}
            onChange={(e) =>
              onPatch({ inject_upstream: e.target.value as StageEntry["inject_upstream"] })
            }
          >
            <option value="none">none</option>
            <option value="findings">findings</option>
            <option value="full">full reports</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-xs mt-4">
          <input
            type="checkbox"
            aria-label={`${label} built-in tools`}
            checked={stage.builtin_tools}
            onChange={(e) => onPatch({ builtin_tools: e.target.checked })}
          />
          <span className="text-text-muted">Built-in tool servers</span>
        </label>
      </div>

      {stage.kind === "debate" && (
        <div className="grid gap-2 sm:grid-cols-3 mt-2">
          <label className="block text-xs">
            <span className="text-text-muted">Max rounds</span>
            <input
              className={input}
              type="number"
              min={1}
              aria-label={`${label} max rounds`}
              value={debate?.max_rounds ?? ""}
              placeholder="global"
              onChange={(e) =>
                onPatch({
                  debate: {
                    max_rounds: Number(e.target.value),
                    consensus_threshold: debate?.consensus_threshold ?? 0.8,
                    sycophancy_check: debate?.sycophancy_check ?? true,
                  },
                })
              }
            />
          </label>
          <label className="block text-xs">
            <span className="text-text-muted">Consensus threshold</span>
            <input
              className={input}
              type="number"
              step="0.05"
              min={0}
              max={1}
              aria-label={`${label} consensus threshold`}
              value={debate?.consensus_threshold ?? ""}
              placeholder="global"
              onChange={(e) =>
                onPatch({
                  debate: {
                    max_rounds: debate?.max_rounds ?? 3,
                    consensus_threshold: Number(e.target.value),
                    sycophancy_check: debate?.sycophancy_check ?? true,
                  },
                })
              }
            />
          </label>
          <label className="flex items-center gap-2 text-xs mt-4">
            <input
              type="checkbox"
              aria-label={`${label} sycophancy check`}
              checked={debate?.sycophancy_check ?? true}
              onChange={(e) =>
                onPatch({
                  debate: {
                    max_rounds: debate?.max_rounds ?? 3,
                    consensus_threshold: debate?.consensus_threshold ?? 0.8,
                    sycophancy_check: e.target.checked,
                  },
                })
              }
            />
            <span className="text-text-muted">Sycophancy check</span>
          </label>
        </div>
      )}

      {error && (
        <p className="text-[11px] text-status-red mt-2" role="alert">
          {error}
        </p>
      )}
    </li>
  );
}
