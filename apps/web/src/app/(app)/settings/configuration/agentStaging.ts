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
import type { AgentDefinitionEntry } from "@/types/settings";

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

/** The map to stage for `core.agents.definitions`. */
export function stagedDefinitions(next: DefinitionMap, saved: DefinitionMap): StagedDefinitionMap {
  // A map that is back where it started is staged as it stands, so the apply
  // bar's revert check recognises it and drops the pending key. A narrowed map
  // never deep-equals the stored one, and would leave "1 change" on screen
  // after an add and a remove that cancelled out.
  if (deepEqual(next, saved)) return next;

  const out: StagedDefinitionMap = {};
  for (const [key, entry] of Object.entries(next)) {
    out[key] = BUILTIN_AGENT_KEYS.has(key)
      ? { role: entry.role, enabled: entry.enabled }
      : entry;
  }
  return out;
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
