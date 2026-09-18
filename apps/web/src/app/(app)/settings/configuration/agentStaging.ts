/**
 * What an edit to the agent map sends, and what the editor draws behind it.
 *
 * The leaf is staged whole — the PATCH body is the entire definition map — so
 * adding one custom agent re-sent every built-in exactly as it came back from
 * `GET /settings`. The API compares a built-in in the body field by field
 * against its seed and refuses the save when they differ, and a store written
 * before a seed's tool list changed holds built-ins that do differ. The result
 * was a console that flagged Judge, Static, Dynamic and Network as invalid
 * ("'judge' is built in; clone it to change it") over an edit nobody made to
 * any of them, and saved nothing. Reporter passed, because its seed is the one
 * with an empty tool list.
 *
 * So a built-in goes out as the only thing an operator may change about it:
 * its role, which is what identifies it, and `enabled`, which is the one lever
 * the settings model accepts. Everything else is filled in from the seed on
 * the way in, which is what the API already does for a partial built-in entry.
 * A custom agent goes out whole, because omitting one is how it is deleted.
 *
 * That leaves the list with a map it cannot draw — a built-in row with no
 * label, prompt or tools — so `displayedDefinitions` puts the stored entry
 * back underneath the staged lever. The two functions are a pair: what is sent
 * and what is shown are different questions, and they were the same answer
 * only for as long as the map was sent whole.
 */

import { deepEqual } from "./deepEqual";
import type {
  AgentDefinitionEntry,
  AgentProbeDetails,
  ProbeResult,
} from "@/types/settings";

/** Re-seeded by the settings model, so they lock rather than delete. */
export const BUILTIN_AGENT_KEYS: ReadonlySet<string> = new Set([
  "static",
  "dynamic",
  "network",
  "judge",
  "reporter",
]);

/** The fields a built-in's staged entry carries. */
export type BuiltinOverride = Pick<AgentDefinitionEntry, "role" | "enabled">;

export type DefinitionMap = Record<string, AgentDefinitionEntry>;
/** The map as it goes on the wire: built-ins narrowed, custom agents whole. */
export type StagedDefinitionMap = Record<string, AgentDefinitionEntry | BuiltinOverride>;

/** The leaf this narrowing belongs to. */
export const AGENT_DEFINITIONS_KEY = "core.agents.definitions";

/** Every built-in of a map reduced to what may be edited about it. */
export function narrowBuiltins(map: DefinitionMap): StagedDefinitionMap {
  const out: StagedDefinitionMap = {};
  for (const [key, entry] of Object.entries(map)) {
    out[key] = BUILTIN_AGENT_KEYS.has(key)
      ? { role: entry.role, enabled: entry.enabled }
      : entry;
  }
  return out;
}

/** The map to stage for `core.agents.definitions`. */
export function stagedDefinitions(next: DefinitionMap, saved: DefinitionMap): StagedDefinitionMap {
  // A map that is back where it started is staged as it stands, so the apply
  // bar's revert check recognises it and drops the pending key. A narrowed map
  // never deep-equals the stored one, and would leave "1 change" on screen
  // after an add and a remove that cancelled out.
  if (deepEqual(next, saved)) return next;
  return narrowBuiltins(next);
}

/**
 * The stored value of a leaf, in the shape a staged edit to it is sent in.
 *
 * The review panel compares what is stored against what is staged, and for
 * this leaf those were two different shapes: the full stored map against the
 * narrowed one. Every built-in then read as "changed: prompt, tools, label",
 * because `undefined` is not `null` — so adding one agent announced that five
 * built-ins were about to be rewritten, which is the sentence the whole fix
 * exists to stop printing. Both sides are narrowed before they are compared.
 */
export function comparableSaved(key: string, saved: unknown): unknown {
  if (key !== AGENT_DEFINITIONS_KEY) return saved;
  if (!saved || typeof saved !== "object" || Array.isArray(saved)) return saved;
  return narrowBuiltins(saved as DefinitionMap);
}

/** The map the editor draws, given what is staged and what is stored. */
export function displayedDefinitions(
  staged: StagedDefinitionMap | null | undefined,
  saved: DefinitionMap,
): DefinitionMap {
  if (!staged) return saved;

  // Stored order first, so a staged edit never reshuffles the list under the
  // operator; anything the edit added follows in the order it was added.
  const out: DefinitionMap = {};
  for (const [key, entry] of Object.entries(saved)) {
    const stagedEntry = staged[key];
    if (stagedEntry === undefined) {
      if (BUILTIN_AGENT_KEYS.has(key)) out[key] = entry;
      continue;
    }
    out[key] = { ...entry, ...stagedEntry };
  }
  for (const [key, entry] of Object.entries(staged)) {
    if (key in out) continue;
    out[key] = entry as AgentDefinitionEntry;
  }
  return out;
}

/** A generic agent with nothing filled in, which is what Add starts from. */
export const EMPTY_DEFINITION: AgentDefinitionEntry = {
  role: "generic",
  label: "",
  prompt: "",
  tools: [],
  static_provider: null,
  enabled: true,
};

/**
 * The definition map with a new entry at `key`: a copy of `from` when one is
 * named, else a blank generic agent.
 *
 * A clone starts from what its source *resolves to*, so an operator can see
 * and edit the built-in prompt rather than guessing it: the source's own
 * `prompt` when it has one, else the resolved text of a probe already made
 * against the source, else `null` — still "the built-in prompt" — with the
 * editor's usual hint to press Resolve first.
 *
 * Shared with the setup guide's "Start from" step so a clone means exactly
 * the same thing wherever it is made.
 *
 * `definitions` is a `DefinitionMap`, which is what keeps a narrowed map from
 * reaching here: `StagedDefinitionMap` does not assign to it, so the mistake
 * H4 was about is a compile error at the call site rather than a clone that
 * quietly loses its tools. Read the map through `displayedDefinitions` first.
 */
export function cloneDefinition(
  definitions: DefinitionMap,
  key: string,
  from?: string,
  sourceProbe?: ProbeResult | "running"
): DefinitionMap {
  const source = from ? definitions[from] : undefined;
  const resolvedDetails =
    sourceProbe && sourceProbe !== "running" && sourceProbe.ok
      ? (sourceProbe.details as AgentProbeDetails | null)
      : null;
  return {
    ...definitions,
    [key]: source
      ? {
          ...source,
          label: source.label ? `${source.label} (copy)` : key,
          prompt: source.prompt ?? resolvedDetails?.prompt ?? null,
          tools: source.tools.map((t) => ({ ...t })),
        }
      : { ...EMPTY_DEFINITION },
  };
}
