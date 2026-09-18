/**
 * What the providers and the teams are called, where a reader has to pick one.
 *
 * The submit dialog offered `r2`, `capa_yara`, `generic_mcp`, `ghidra`,
 * `cape2`, `rest`, `triage`, `upload` and `team_lead` — registry keys, every
 * one of them, asked of somebody deciding how to analyse a sample. The key is
 * still worth showing, because it is what the job config carries and what a
 * log line says, so it follows the name rather than standing in for it.
 *
 * A key nothing here names is read back from its key rather than dropped: a
 * provider added to the registry appears in this list the day it is
 * registered, and the only cost of not adding it here is that it reads as
 * itself.
 */

import { humaniseKey } from "./humanise";

/** `static.provider` keys, as their own projects write them. */
const STATIC_PROVIDER: Record<string, string> = {
  capa_yara: "capa + YARA",
  generic_mcp: "Any MCP tool server",
  ghidra: "Ghidra",
  r2: "radare2",
  none: "No static provider",
};

/** `sandbox.provider` keys. */
const SANDBOX_PROVIDER: Record<string, string> = {
  cape2: "CAPE v2",
  mock: "Mock sandbox",
  rest: "Any HTTP sandbox",
  triage: "Hatching Triage",
  upload: "A report you attach",
};

function labelled(map: Record<string, string>, key: string): string {
  const name = map[key] ?? humaniseKey(key);
  return name === key ? key : `${name} (${key})`;
}

/** The static provider, named, with its key after it. */
export function staticProviderLabel(key: string): string {
  return labelled(STATIC_PROVIDER, key);
}

/** The sandbox provider, named, with its key after it. */
export function sandboxProviderLabel(key: string): string {
  return labelled(SANDBOX_PROVIDER, key);
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
