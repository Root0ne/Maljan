/** The teams the settings model seeds (`config.BUILTIN_PROFILES`). Used only
 *  when the API served no default for the leaf, so an API that cannot name
 *  them keeps today's behaviour: these stay "built in". */
const FALLBACK_SEEDED_PROFILES: ReadonlySet<string> = new Set([
  "default",
  "measurement",
  "mobile",
  "deep_static",
  "team_lead",
]);

/**
 * The teams the settings model seeds, which lock rather than delete: the keys
 * of the catalog entry's own default, so a team the API adds or retires moves
 * the lock with it. A default the API did not send, or sent empty, falls back
 * to the five teams every release has seeded.
 */
export function seededProfiles(entryDefault: unknown): ReadonlySet<string> {
  if (entryDefault && typeof entryDefault === "object" && !Array.isArray(entryDefault)) {
    const keys = Object.keys(entryDefault as Record<string, unknown>);
    if (keys.length > 0) return new Set(keys);
  }
  return FALLBACK_SEEDED_PROFILES;
}
