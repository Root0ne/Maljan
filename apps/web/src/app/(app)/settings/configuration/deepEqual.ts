/**
 * Structural equality for setting values.
 *
 * A composite leaf (the server map, the agent definitions) stages a whole
 * object, so "is this back where it started" is not a `===` question. Key
 * order is not: two maps with the same entries written in a different order
 * are the same setting.
 *
 * The three keyed-map editors (`ServerMapEditor`, `AgentDefinitionsEditor`,
 * `ProfilesEditor` via `describeChange`/`importPreview`) and `useSettings`
 * each carried their own copy of this rule; this is the one copy.
 */
export function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a == null || b == null) return a === b;
  if (typeof a !== typeof b) return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((item, i) => deepEqual(item, b[i]));
  }
  if (typeof a !== "object") return false;
  const left = a as Record<string, unknown>;
  const right = b as Record<string, unknown>;
  const keys = Object.keys(left);
  if (keys.length !== Object.keys(right).length) return false;
  return keys.every((k) => k in right && deepEqual(left[k], right[k]));
}
