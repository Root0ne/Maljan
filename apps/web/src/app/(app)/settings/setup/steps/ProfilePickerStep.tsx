"use client";

import { useState } from "react";
import type { ProfileEntry } from "@/types/settings";
import { mapKeyError } from "../../configuration/mapEditorHelpers";
import { useSettingsContext } from "../../configuration/SettingsContext";
import { withAgentInProfile, withoutProfile } from "./profilePicker";
import { stateString, type GuideStepProps } from "./types";

const PROFILES_KEY = "core.agents.profiles";
const ACTIVE_KEY = "core.agents.profile";
/** The radio value for "not one of the existing profiles". */
const NEW_PROFILE = " new";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent";

/**
 * "Add this analyst to a profile": the last question the agent guide asks.
 *
 * A definition nothing runs is a definition nobody sees, so the guide ends by
 * putting the new agent into a run order — an existing profile, or a new one
 * copied from whichever profile is active now — and optionally makes that
 * profile the active one. Both are ordinary catalog leaves
 * (`core.agents.profiles`, `core.agents.profile`), staged the way the
 * console's profiles editor stages them, so the guide's Apply is still one
 * PATCH.
 *
 * Every change first undoes this step's previous pick and then applies the
 * new one, so picking profile A and then B leaves the agent in B alone, and
 * clearing a half-typed new name takes the half-typed profile back out of
 * what Apply would send. Only what this step staged is ever taken back: a
 * pending active-profile change made elsewhere is left where it is.
 */
export default function ProfilePickerStep({ state, setState }: GuideStepProps) {
  const ctx = useSettingsContext();
  const entry = ctx.entriesByKey[PROFILES_KEY];
  const profiles = (ctx.pending[PROFILES_KEY] ??
    ctx.values[PROFILES_KEY]?.value ??
    entry?.default ??
    {}) as Record<string, ProfileEntry>;
  const activeProfile = String(ctx.effectiveValue(ACTIVE_KEY) ?? "default");

  /** The profile map this step started from: what "undo my pick" restores to,
   *  so a pick is never applied on top of the previous one. */
  const [base] = useState<Record<string, ProfileEntry>>(profiles);
  const [choice, setChoice] = useState<string>("");
  const [newKey, setNewKey] = useState("");
  const [makeActive, setMakeActive] = useState(false);
  const [keyError, setKeyError] = useState<string | null>(null);
  /** The profile this step last wrote the agent into, and the profile it last
   *  made active — the two things it is allowed to take back. */
  const [ownProfile, setOwnProfile] = useState<string | null>(null);
  const [ownActive, setOwnActive] = useState<string | null>(null);

  const agentKey = stateString(state, "agentKey");

  if (!entry) {
    return <p role="alert">The agent profiles are not in the catalog.</p>;
  }
  if (agentKey === null) {
    return (
      <p className="text-sm text-text-secondary">
        Create the analyst first; this step adds it to a profile.
      </p>
    );
  }

  const stageChoice = (nextChoice: string, nextName: string, active: boolean) => {
    /* This step's previous pick, undone: a profile it created goes away, a
     * profile it edited goes back to the entry it had when the step opened.
     * Everything else in the map — including edits made in the console before
     * the guide was opened — is left exactly as it is. */
    const undone =
      ownProfile === null
        ? profiles
        : ownProfile in base
          ? { ...profiles, [ownProfile]: base[ownProfile] }
          : withoutProfile(profiles, ownProfile);

    const commit = (map: Record<string, ProfileEntry>, key: string | null) => {
      // `stage` drops the key from the pending patch when the value is back
      // where it started, so undoing a pick leaves no phantom change behind.
      ctx.stage(PROFILES_KEY, map);
      setOwnProfile(key);
      setState({ profileKey: key });
      if (key !== null && active) {
        ctx.stage(ACTIVE_KEY, key);
        setOwnActive(key);
      } else if (ownActive !== null) {
        ctx.unstage(ACTIVE_KEY);
        setOwnActive(null);
      }
    };

    if (nextChoice === NEW_PROFILE) {
      const key = nextName.trim();
      if (key === "") {
        // A cleared name box is not an error, but it is also no longer a
        // profile: whatever the half-typed name staged comes back out.
        setKeyError(null);
        commit(undone, null);
        return;
      }
      const problem = mapKeyError(key, base, "profile");
      if (problem) {
        setKeyError(problem);
        commit(undone, null);
        return;
      }
      setKeyError(null);
      commit(withAgentInProfile(undone, key, agentKey, activeProfile), key);
      return;
    }
    if (nextChoice === "") {
      setKeyError(null);
      commit(undone, null);
      return;
    }
    setKeyError(null);
    commit(withAgentInProfile(undone, nextChoice, agentKey), nextChoice);
  };

  return (
    <fieldset className="border-0 p-0 m-0" data-testid="profile-picker">
      <legend className="sr-only">Add to a profile</legend>
      <div className="space-y-2">
        {Object.entries(base).map(([key, profile]) => (
          <label key={key} className="flex gap-2 items-center text-sm text-text-primary">
            <input
              type="radio"
              name="guide-profile"
              value={key}
              checked={choice === key}
              onChange={() => {
                setChoice(key);
                stageChoice(key, newKey, makeActive);
              }}
            />
            <span className="font-mono">{key}</span>
            <span className="text-xs text-text-secondary">
              {profile.label ? `${profile.label} — ` : ""}
              {profile.analysts.length} analyst
              {profile.analysts.length === 1 ? "" : "s"}
            </span>
          </label>
        ))}
        <label className="flex gap-2 items-center text-sm text-text-primary">
          <input
            type="radio"
            name="guide-profile"
            value={NEW_PROFILE}
            checked={choice === NEW_PROFILE}
            onChange={() => {
              setChoice(NEW_PROFILE);
              stageChoice(NEW_PROFILE, newKey, makeActive);
            }}
          />
          Create a new profile from <span className="font-mono">{activeProfile}</span>
        </label>
        <input
          className={input}
          placeholder="new profile name"
          aria-label="new profile name"
          value={newKey}
          onChange={(e) => {
            setNewKey(e.target.value);
            setChoice(NEW_PROFILE);
            stageChoice(NEW_PROFILE, e.target.value, makeActive);
          }}
        />
        <label className="flex gap-2 items-center text-sm text-text-primary">
          <input
            type="checkbox"
            checked={makeActive}
            onChange={(e) => {
              setMakeActive(e.target.checked);
              stageChoice(choice, newKey, e.target.checked);
            }}
          />
          Make it the active profile
        </label>
      </div>
      {keyError && (
        <p className="text-[11px] text-status-red mt-2" role="alert">
          {keyError}
        </p>
      )}
    </fieldset>
  );
}
