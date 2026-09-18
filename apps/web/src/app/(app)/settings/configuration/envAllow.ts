/**
 * The environment names a built-in sidecar is always started with.
 *
 * Mirrors `REQUIRED_ENV_ALLOW` in `src/maljan/core/config.py`. The API puts
 * these names back on load, on save, in the values it hands this editor and in
 * the connection test, because a child that loses them refuses the run's own
 * sample or stages an upload where nothing else looks for it. The editor draws
 * them as fixed rather than as lines in the box: a deletion the API silently
 * undoes leaves an admin believing they narrowed a server they did not.
 *
 * Only these. Every other name a built-in ships with — `threatintel`'s two API
 * keys — is a default an operator may take away and keep away, so it is
 * ordinary text in the box below.
 */
export const REQUIRED_ENV_ALLOW: Record<string, readonly string[]> = {
  analysis: ["MALJAN_STAGING_DIR", "MALJAN_STAGING_TTL_HOURS", "MALJAN_SAMPLE_ROOTS"],
  network: ["MALJAN_STAGING_DIR", "MALJAN_SAMPLE_ROOTS"],
};

/** The names this server is passed whatever the stored registry says. */
export function requiredEnvNames(serverKey: string): readonly string[] {
  return REQUIRED_ENV_ALLOW[serverKey] ?? [];
}

/** The part of `env_allow` an admin owns: what is left once the fixed names are out. */
export function addedEnvNames(serverKey: string, envAllow: readonly string[]): string[] {
  const required = new Set(requiredEnvNames(serverKey));
  return envAllow.filter((name) => !required.has(name));
}

/**
 * The whole `env_allow` to stage: the fixed names, then the typed ones.
 *
 * Same order and same de-duplication as `builtin_env_allow` on the API side, so
 * what the editor stages is what the server stores and what the child is
 * started with — the map is sent whole, and a round trip must not rewrite it.
 */
export function withRequiredEnvNames(serverKey: string, typed: readonly string[]): string[] {
  return [...new Set([...requiredEnvNames(serverKey), ...typed])];
}
