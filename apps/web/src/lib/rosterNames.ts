/**
 * What a run calls its agents and its stages.
 *
 * The roster a job carries is the only place the operator's own names live:
 * the pipeline publishes under registry keys, and `ahmet_1` is what the second
 * analyst somebody called "Ahmet" is keyed by. Every surface that names a
 * participant reads the roster through here, so the header strip, the
 * participants bar, the conversation and the per-agent results table cannot
 * disagree about who took part.
 *
 * The fallback is the caller's, because the two sensible ones differ: a table
 * of rows the pipeline published shows the key it published under, and a chat
 * bubble reads better with the key made readable.
 */

import type { JobRoster } from "@/types/events";

export interface RosterNames {
  /** The name to draw for an agent key. */
  agent: (key: string) => string;
  /** The name to draw for a stage key. */
  stage: (key: string) => string;
  /** Whether the roster names this agent at all. */
  hasAgent: (key: string) => boolean;
}

/** The key itself, which is what a run with no roster has to show. */
const KEY_ITSELF = (key: string) => key;

export function rosterNames(
  roster: JobRoster | null | undefined,
  fallback: (key: string) => string = KEY_ITSELF,
): RosterNames {
  const agents = new Map<string, string>();
  const stages = new Map<string, string>();

  for (const agent of roster?.agents ?? []) {
    if (agent.label) agents.set(agent.key, agent.label);
  }
  for (const stage of roster?.stages ?? []) {
    if (stage.label) stages.set(stage.key, stage.label);
  }

  return {
    agent: (key) => agents.get(key) ?? fallback(key),
    stage: (key) => stages.get(key) ?? fallback(key),
    hasAgent: (key) => agents.has(key),
  };
}
