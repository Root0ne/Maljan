"use client";

import { useState } from "react";
import type {
  AgentDefinitionEntry,
  CatalogEntry,
  ProfileEntry,
  SettingValue,
} from "@/types/settings";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

const SLUG = /^[a-z][a-z0-9_-]{0,31}$/;
/** Seeded by the settings model, so it locks rather than deletes. */
const BUILTIN_PROFILES = new Set(["default"]);

/**
 * The whole `core.agents.profiles` leaf, as a list of cards.
 *
 * The list inside a card is ordered and the order is meaningful: it is the
 * sequential run order of the analysts, which is why this offers move up and
 * move down rather than a set of tick boxes. "Set active" stages
 * `core.agents.profile` through `onSetActive`, so choosing a profile and
 * building it are one apply rather than two.
 */
export default function ProfilesEditor({
  entry,
  current,
  staged,
  definitions,
  activeProfile,
  onChange,
  onSetActive,
}: {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown;
  definitions: Record<string, AgentDefinitionEntry>;
  activeProfile: string;
  onChange: (value: Record<string, ProfileEntry>) => void;
  onSetActive: (name: string) => void;
}) {
  const value = (staged ?? current?.value ?? entry.default ?? {}) as Record<string, ProfileEntry>;
  const [newKey, setNewKey] = useState("");
  const [keyError, setKeyError] = useState<string | null>(null);

  const candidates = Object.entries(definitions)
    .filter(([, d]) => d.enabled && d.role !== "judge")
    .map(([k]) => k);

  const put = (key: string, next: Partial<ProfileEntry>) =>
    onChange({ ...value, [key]: { ...value[key], ...next } });

  const move = (key: string, index: number, by: number) => {
    const analysts = [...value[key].analysts];
    const target = index + by;
    if (target < 0 || target >= analysts.length) return;
    [analysts[index], analysts[target]] = [analysts[target], analysts[index]];
    put(key, { analysts });
  };

  const add = (from?: string) => {
    const key = newKey.trim();
    if (!SLUG.test(key)) {
      setKeyError("lowercase, starts with a letter, at most 32 of a-z 0-9 - _");
      return;
    }
    if (key in value) {
      setKeyError("a profile with that name already exists");
      return;
    }
    setKeyError(null);
    setNewKey("");
    const source = from ? value[from] : undefined;
    onChange({
      ...value,
      [key]: source
        ? { label: source.label ? `${source.label} (copy)` : key, analysts: [...source.analysts] }
        : { label: "", analysts: [] },
    });
  };

  return (
    <div className="space-y-3" data-testid="profiles-editor">
      {Object.entries(value).map(([key, profile]) => {
        const locked = BUILTIN_PROFILES.has(key);
        const unused = candidates.filter((c) => !profile.analysts.includes(c));
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
                  className="text-xs text-accent-strong"
                  onClick={() => onSetActive(key)}
                >
                  Set active
                </button>
                <button
                  type="button"
                  className="text-xs text-accent-strong"
                  onClick={() => add(key)}
                >
                  Clone
                </button>
                {!locked && (
                  <button
                    type="button"
                    className="text-xs text-text-secondary"
                    onClick={() => {
                      const next = { ...value };
                      delete next[key];
                      onChange(next);
                    }}
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

            <ol className="mt-2 space-y-1">
              {profile.analysts.map((analyst, index) => (
                <li key={analyst} className="flex items-center gap-2 text-xs">
                  <span className="font-mono text-text-primary">
                    {index + 1}. {analyst}
                  </span>
                  <button
                    type="button"
                    className="text-[11px] text-text-secondary disabled:opacity-40"
                    aria-label={`${key} move ${analyst} up`}
                    disabled={locked || index === 0}
                    onClick={() => move(key, index, -1)}
                  >
                    up
                  </button>
                  <button
                    type="button"
                    className="text-[11px] text-text-secondary disabled:opacity-40"
                    aria-label={`${key} move ${analyst} down`}
                    disabled={locked || index === profile.analysts.length - 1}
                    onClick={() => move(key, index, 1)}
                  >
                    down
                  </button>
                  <button
                    type="button"
                    className="text-[11px] text-text-secondary disabled:opacity-40"
                    aria-label={`${key} remove ${analyst}`}
                    disabled={locked}
                    onClick={() =>
                      put(key, { analysts: profile.analysts.filter((a) => a !== analyst) })
                    }
                  >
                    remove
                  </button>
                </li>
              ))}
              {profile.analysts.length === 0 && (
                <li className="text-[11px] text-status-red" role="alert">
                  a profile needs at least one analyst
                </li>
              )}
            </ol>

            {!locked && unused.length > 0 && (
              <label className="block text-xs mt-2">
                <span className="text-text-muted">Add analyst</span>
                <select
                  className={input}
                  aria-label={`${key} add analyst`}
                  value=""
                  onChange={(e) =>
                    e.target.value &&
                    put(key, { analysts: [...profile.analysts, e.target.value] })
                  }
                >
                  <option value="">choose an enabled analyst</option>
                  {unused.map((c) => (
                    <option key={c} value={c}>
                      {c}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
        );
      })}

      <div className="flex items-center gap-2">
        <input
          className={input}
          placeholder="new profile name"
          aria-label="new profile name"
          value={newKey}
          onChange={(e) => setNewKey(e.target.value)}
        />
        <button type="button" className="text-xs text-accent-strong" onClick={() => add()}>
          Add profile
        </button>
      </div>
      {keyError && (
        <p className="text-[11px] text-status-red" role="alert">
          {keyError}
        </p>
      )}
    </div>
  );
}
