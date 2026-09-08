import { describe, expect, it } from "vitest";
import { firstGroupPath, groupsBySection, pathForKey, resolveGroup } from "../sections";
import type { SettingsSchema, CatalogEntry } from "@/types/settings";
const entry = (key: string, group: string): CatalogEntry => ({ key, namespace: "core", path: key.slice(5), type: "int", default: 1, nullable: false, choices: null, minimum: null, maximum: null, secret: false, group, title: key, description: "", applies: "next_job", editable: true, reason: null, probe: null, applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false });
const schema: SettingsSchema = { secrets_available: true, groups: [
  { key: "agents", title: "Agents", description: "", entries: [entry("core.agents.profiles", "agents"), entry("core.agents.profile", "agents"), entry("core.react_agent_timeout", "agents")] },
  { key: "llm", title: "LLM & model", description: "", entries: [entry("core.llm.provider", "llm")] },
  { key: "mystery", title: "Mystery", description: "", entries: [entry("core.mystery.x", "mystery")] },
] };
describe("sections", () => {
  it("orders sections and puts unknown groups last under platform", () => {
    const s = groupsBySection(schema);
    expect(s.map((x) => x.section.key)).toEqual(["models", "agents", "platform"]);
    expect(s.at(-1)!.groups.map((g) => g.key)).toEqual(["mystery"]);
  });
  it("splits profiles out of the agents group", () => {
    expect(resolveGroup(schema, "agents", "profiles")!.entries.map((e) => e.key)).toEqual(["core.agents.profiles", "core.agents.profile"]);
    expect(resolveGroup(schema, "agents", "agents")!.entries.map((e) => e.key)).toEqual(["core.react_agent_timeout"]);
    expect(resolveGroup(schema, "agents", "nope")).toBeNull();
  });
  it("does not let platform claim a group another section already owns", () => {
    expect(resolveGroup(schema, "platform", "llm")).toBeNull();
    expect(resolveGroup(schema, "platform", "mystery")).not.toBeNull();
  });
  it("links keys to the page that renders them", () => {
    expect(firstGroupPath(schema)).toBe("/settings/configuration/models/llm");
    expect(pathForKey(schema, "core.agents.profile")).toBe("/settings/configuration/agents/profiles");
    expect(pathForKey(schema, "core.mystery.x")).toBe("/settings/configuration/platform/mystery");
  });
});
