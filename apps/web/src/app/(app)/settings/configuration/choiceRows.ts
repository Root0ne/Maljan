/**
 * A list of names an editor offers as checkboxes, read against a stored list.
 *
 * Two editors draw one: the agent detail's input slices (`data_sources`,
 * offered from the vocabulary the API serves) and the server detail's agent
 * bindings (`agents`, offered from the agent roster). In both, the stored list
 * may name something the offer does not hold — a value written by an import or
 * by an older release — and that name is drawn, marked and kept, never
 * dropped by the next unrelated edit. Unticking it is the one way it leaves.
 */

import type { ToolRefEntry } from "@/types/settings";

export interface ChoiceRow {
  key: string;
  /** False for a stored name the offer does not hold. */
  known: boolean;
}

/** Every offered name in its order, then every stored name outside the offer,
 *  in its stored order. */
export function choiceRows(offered: readonly string[], stored: readonly string[]): ChoiceRow[] {
  const known = new Set(offered);
  const rows: ChoiceRow[] = [...known].map((key) => ({ key, known: true }));
  const seen = new Set(known);
  for (const key of stored) {
    if (seen.has(key)) continue;
    seen.add(key);
    rows.push({ key, known: false });
  }
  return rows;
}

/** The stored list with `key` ticked or unticked; every other name, known or
 *  not, stays where it was. */
export function toggleChoice(stored: readonly string[], key: string, on: boolean): string[] {
  if (on) return stored.includes(key) ? [...stored] : [...stored, key];
  return stored.filter((name) => name !== key);
}

/**
 * The agents a tool server may be bound to, as the save that sends the
 * binding will judge them: the seeded agents, always known, and the
 * definition map in force after it.
 *
 * With no definition edit staged that map is the stored one, which the API
 * serves as `agent_keys` beside the map on screen. With one staged, the save
 * sends the staged map whole, so the map on screen is all there is: an agent
 * added a moment ago is offered, and one whose removal is staged is not, so
 * a binding to it is drawn as unknown before Apply rather than refused by it.
 */
export function rosterAgentKeys({
  served,
  seeded,
  definitions,
  definitionsStaged,
}: {
  served: readonly string[] | null | undefined;
  seeded: readonly string[] | null | undefined;
  definitions: Record<string, unknown>;
  definitionsStaged: boolean;
}): string[] {
  const rest = definitionsStaged ? (seeded ?? []) : (served ?? []);
  return [...new Set([...Object.keys(definitions), ...rest])];
}

/** The job's sandbox-report tools, in the shape the API stores the reference
 *  (`ToolRef(kind="sandbox")`): it names nothing else, since a job has one
 *  report. */
export const SANDBOX_REF: ToolRefEntry = { kind: "sandbox", server: null, name: null };
