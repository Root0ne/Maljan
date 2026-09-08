import type { CatalogEntry, SettingsSchema } from "@/types/settings";

export interface SectionDef {
  key: "models" | "tools" | "agents" | "layers" | "platform";
  title: string;
  groups: string[];
}

/** Maps the 16 backend catalog groups onto five settings-page sections. Group
 *  keys not literally listed here fall through to "platform", in schema
 *  order, titled from the schema — see `groupsBySection`. */
export const SECTIONS: SectionDef[] = [
  { key: "models", title: "Models", groups: ["llm", "providers"] },
  { key: "tools", title: "Analysis tools", groups: ["static", "sandbox", "mcp", "memory"] },
  { key: "agents", title: "Agents and pipeline", groups: ["agents", "profiles", "negotiation", "chunking"] },
  { key: "layers", title: "Layers and reporting", groups: ["analysis", "reporting"] },
  { key: "platform", title: "Platform", groups: ["enrichment", "api", "tracing", "frontier", "system"] },
];

/** Groups synthesised from a slice of a real backend group's entries rather
 *  than mirroring a backend group one-to-one. */
export const VIRTUAL_GROUPS: Record<
  string,
  { fromGroup: string; title: string; description: string; keys: string[] }
> = {
  profiles: {
    fromGroup: "agents",
    title: "Profiles",
    description:
      "Which analysts run, in which order, and which profile is active.",
    keys: ["core.agents.profiles", "core.agents.profile"],
  },
};

export interface RailGroup {
  key: string;
  title: string;
  path: string;
  section: SectionDef["key"];
}

function railPath(section: SectionDef["key"], group: string): string {
  return `/settings/configuration/${section}/${group}`;
}

/** Every backend group key `SECTIONS`/`VIRTUAL_GROUPS` accounts for, so an
 *  unlisted schema group can be told apart from one that legitimately has no
 *  entries yet. Shared by `groupsBySection` (who falls into "platform") and
 *  `resolveGroup` (whether "platform" may claim a given group key). */
export function knownBackendGroups(): Set<string> {
  const known = new Set<string>();
  for (const section of SECTIONS) {
    for (const groupKey of section.groups) {
      const virtual = VIRTUAL_GROUPS[groupKey];
      known.add(virtual ? virtual.fromGroup : groupKey);
    }
  }
  return known;
}

export function groupsBySection(
  schema: SettingsSchema
): { section: SectionDef; groups: RailGroup[] }[] {
  const schemaByKey = new Map(schema.groups.map((g) => [g.key, g]));
  const known = knownBackendGroups();
  const result: { section: SectionDef; groups: RailGroup[] }[] = [];

  for (const section of SECTIONS) {
    const groups: RailGroup[] = [];
    for (const groupKey of section.groups) {
      const virtual = VIRTUAL_GROUPS[groupKey];
      if (virtual) {
        if (schemaByKey.has(virtual.fromGroup)) {
          groups.push({
            key: groupKey,
            title: virtual.title,
            path: railPath(section.key, groupKey),
            section: section.key,
          });
        }
        continue;
      }
      const schemaGroup = schemaByKey.get(groupKey);
      if (schemaGroup) {
        groups.push({
          key: groupKey,
          title: schemaGroup.title,
          path: railPath(section.key, groupKey),
          section: section.key,
        });
      }
    }
    if (section.key === "platform") {
      for (const schemaGroup of schema.groups) {
        if (!known.has(schemaGroup.key)) {
          groups.push({
            key: schemaGroup.key,
            title: schemaGroup.title,
            path: railPath("platform", schemaGroup.key),
            section: "platform",
          });
        }
      }
    }
    if (groups.length > 0) result.push({ section, groups });
  }
  return result;
}

export function resolveGroup(
  schema: SettingsSchema,
  section: string,
  group: string
): { title: string; description: string; entries: CatalogEntry[]; backendGroup: string } | null {
  const sectionDef = SECTIONS.find((s) => s.key === section);
  if (!sectionDef) return null;
  const belongsToSection =
    sectionDef.groups.includes(group) ||
    // Unknown backend groups fall through to "platform" without being listed
    // in SECTIONS.groups; accept them there — but only if no other section
    // has already claimed the group, so "platform" can't leak a group (e.g.
    // "llm") that actually belongs to "models".
    (section === "platform" &&
      !knownBackendGroups().has(group) &&
      schema.groups.some((g) => g.key === group));
  if (!belongsToSection) return null;

  const virtual = VIRTUAL_GROUPS[group];
  if (virtual) {
    const backendGroup = schema.groups.find((g) => g.key === virtual.fromGroup);
    if (!backendGroup) return null;
    const entries = virtual.keys
      .map((key) => backendGroup.entries.find((e) => e.key === key))
      .filter((e): e is CatalogEntry => e !== undefined);
    return {
      title: virtual.title,
      description: virtual.description,
      entries,
      backendGroup: virtual.fromGroup,
    };
  }

  const backendGroup = schema.groups.find((g) => g.key === group);
  if (!backendGroup) return null;

  const excludedKeys = new Set<string>();
  for (const vg of Object.values(VIRTUAL_GROUPS)) {
    if (vg.fromGroup === group) vg.keys.forEach((k) => excludedKeys.add(k));
  }
  const entries = backendGroup.entries.filter((e) => !excludedKeys.has(e.key));
  return {
    title: backendGroup.title,
    description: backendGroup.description,
    entries,
    backendGroup: group,
  };
}

export function firstGroupPath(schema: SettingsSchema): string {
  const sections = groupsBySection(schema);
  return sections[0]?.groups[0]?.path ?? "";
}

export function pathForKey(schema: SettingsSchema, key: string): string {
  for (const [virtualKey, virtual] of Object.entries(VIRTUAL_GROUPS)) {
    if (virtual.keys.includes(key)) {
      const sectionDef = SECTIONS.find((s) => s.groups.includes(virtualKey));
      if (sectionDef) return railPath(sectionDef.key, virtualKey);
    }
  }
  const backendGroup = schema.groups.find((g) =>
    g.entries.some((e) => e.key === key)
  );
  if (!backendGroup) return "";
  for (const { groups } of groupsBySection(schema)) {
    const railGroup = groups.find((g) => g.key === backendGroup.key);
    if (railGroup) return railGroup.path;
  }
  return "";
}
