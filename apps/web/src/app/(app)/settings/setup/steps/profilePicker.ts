import type { ProfileEntry } from "@/types/settings";

/**
 * The profile map with `agentKey` in `profileKey`'s run order.
 *
 * An existing profile keeps everything it has and gains the agent at the end
 * of its analysts, unless it already runs it — an operator who walks back
 * through the guide must not end up with the same analyst twice.
 *
 * A profile that does not exist yet is created from `from`, the profile the
 * guide offered to copy (the active one): its analysts, plus the agent, and
 * the label the console's Clone gives a copy — `"<label> (copy)"`, falling
 * back to the new key when the source has no label, exactly as
 * `ProfilesEditor.add()` names one.
 */
export function withAgentInProfile(
  profiles: Record<string, ProfileEntry>,
  profileKey: string,
  agentKey: string,
  from?: string
): Record<string, ProfileEntry> {
  const target = profiles[profileKey];
  if (target) {
    if (target.analysts.includes(agentKey)) return { ...profiles };
    return {
      ...profiles,
      [profileKey]: { ...target, analysts: [...target.analysts, agentKey] },
    };
  }
  const source = from ? profiles[from] : undefined;
  const analysts = source ? [...source.analysts] : [];
  if (!analysts.includes(agentKey)) analysts.push(agentKey);
  return {
    ...profiles,
    [profileKey]: {
      label: source?.label ? `${source.label} (copy)` : profileKey,
      analysts,
    },
  };
}

/** The map without `key`, leaving every other profile as it was. */
export function withoutProfile(
  profiles: Record<string, ProfileEntry>,
  key: string
): Record<string, ProfileEntry> {
  const out = { ...profiles };
  delete out[key];
  return out;
}
