/**
 * What the providers and the teams are called, where a reader has to pick one.
 *
 * The submit dialog offered registry keys, every one of them, asked of
 * somebody deciding how to analyse a sample. The key is still worth showing,
 * because it is what the job config carries and what a log line says, so it
 * follows the name rather than standing in for it.
 *
 * A provider's name is the title it declares for itself, served on its
 * selector's catalog entry (`choice_titles`); a key nothing names is read back
 * from its key rather than dropped, so a provider added to a registry appears
 * the day it is registered.
 */

import { humaniseKey } from "./humanise";

/** A provider, named by the title it declares, with its key after it. */
export function providerLabel(
  key: string,
  titles?: Record<string, string> | null
): string {
  const name = titles?.[key] ?? humaniseKey(key);
  return name === key ? key : `${name} (${key})`;
}

/**
 * The team, named.
 *
 * The seeded teams are keyed after what they are — `deep_static`, `team_lead`,
 * `measurement` — so reading the key back is the whole of the name, and there
 * is nothing left for the key to add.
 */
export function profileLabel(key: string): string {
  return humaniseKey(key);
}
