/**
 * What the three keyed-map editors all had a copy of.
 *
 * `ServerMapEditor`, `AgentDefinitionsEditor` and
 * `ProfilesEditor` each carried the same slug regex, the same "already exists"
 * branch, the same merge-one-entry helper and the same clone-key arithmetic,
 * near-verbatim. Three copies of one rule drift; this is the rule.
 */

/** The key shape every one of these maps accepts. Mirrors `AGENT_KEY_PATTERN`
 *  and the server-map key rule in `src/maljan/core/config.py`. */
export const MAP_KEY = /^[a-z][a-z0-9_-]{0,31}$/;

export const MAP_KEY_RULE =
  "lowercase, starts with a letter, at most 32 of a-z 0-9 - _";

/**
 * Why this key cannot be used, or `null` when it can.
 *
 * `noun` names the thing being added ("agent", "profile", "server") so the
 * duplicate message reads as the editor's own.
 */
export function mapKeyError(
  key: string,
  taken: Record<string, unknown>,
  noun: string,
  reserved?: ReadonlySet<string>,
): string | null {
  if (!MAP_KEY.test(key)) return MAP_KEY_RULE;
  if (key in taken) return `a ${noun} with that name already exists`;
  if (reserved?.has(key)) return `'${key}' is reserved for a provider-owned server.`;
  return null;
}

/**
 * The name a clone of `source` takes when the operator did not type one.
 *
 * Clone used to do nothing at all with an empty
 * name box — no card, no message, no request — so the documented "clone an
 * agent" flow looked broken. `<source>_copy`, then `_copy2`, `_copy3`… so
 * cloning twice does not collide, truncated to the 32 characters the key rule
 * allows.
 */
export function copyKey(source: string, taken: Record<string, unknown>): string {
  const base = source.slice(0, 26);
  for (let n = 1; ; n += 1) {
    const candidate = n === 1 ? `${base}_copy` : `${base}_copy${n}`;
    if (!(candidate in taken)) return candidate;
  }
}

/** One entry merged back into the map, leaving the others untouched. */
export function putEntry<T>(
  map: Record<string, T>,
  key: string,
  next: Partial<T>,
): Record<string, T> {
  return { ...map, [key]: { ...map[key], ...next } };
}

/** The map without `key`. */
export function removeEntry<T>(map: Record<string, T>, key: string): Record<string, T> {
  const out = { ...map };
  delete out[key];
  return out;
}

/**
 * Which button an inline message belongs under.
 *
 * The editors used to set one `keyError` string and render it beside the name
 * box at the bottom of the editor, far from the Clone button on the card that
 * was actually pressed. The message now travels with the place it came from —
 * `"add"` for the name box, otherwise the key of the card whose Clone was
 * pressed.
 */
export interface KeyError {
  at: string;
  message: string;
}

export const ADD_BUTTON = "add";

export { deepEqual } from "./deepEqual";
