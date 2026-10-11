import {
  AGENT_DEFINITIONS_KEY,
  BUILTIN_AGENT_KEYS,
} from "../configuration/agentStaging";
import type { GuideId } from "./guides";
import { choiceFacts, choiceTitle, LLM_SELECTOR } from "@/lib/providerFacts";
import type { SettingsSchema } from "@/types/settings";

/** Reads the value a key currently has — staged if it is staged, else stored.
 *  Exactly `SettingsContextValue.effectiveValue`. */
export type EffectiveValue = (key: string) => unknown;

/** Whether a secret key has a value stored on the server. A secret's value
 *  never travels, so `effective` cannot answer this: `values[key].is_set`
 *  does. */
export type IsSet = (key: string) => boolean;

/** The provider's title, as it declares it in the settings schema. */
export function llmProviderTitle(
  provider: string,
  schema?: SettingsSchema | null
): string {
  return choiceTitle(schema, LLM_SELECTOR, provider);
}

function text(value: unknown): string {
  if (value === null || value === undefined) return "";
  return String(value).trim();
}

function record(value: unknown): Record<string, { enabled?: boolean }> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, { enabled?: boolean }>)
    : {};
}

function countEnabled(value: unknown, skip: (key: string) => boolean = () => false): number {
  return Object.entries(record(value)).filter(([key, v]) => !skip(key) && v?.enabled === true)
    .length;
}

/** Agent keys the backend ships; anything else in the definitions map is a
 *  custom analyst. */
const BUILTIN_AGENTS = BUILTIN_AGENT_KEYS;

/**
 * Whether the language-model settings could plausibly run an analysis: a
 * hosted provider with one of its credential keys stored, or a provider run
 * locally with its address set. Which it is, and which keys hold its
 * credential and its address, the provider declares in the settings schema.
 * While the schema is still loading, a stored key or a set address of the
 * provider's own block counts. Decides whether `/settings/configuration`
 * lands on the console or on the guide hub.
 */
export function llmLooksConfigured(
  effective: EffectiveValue,
  isSet: IsSet,
  schema?: SettingsSchema | null
): boolean {
  const provider = text(effective(LLM_SELECTOR));
  if (!provider) return false;
  const facts = choiceFacts(schema, LLM_SELECTOR, provider);
  const address = facts.base_url_key ?? `core.llm.${provider}.base_url`;
  if (facts.hosted === undefined) {
    return isSet(`core.llm.${provider}.api_key`) || text(effective(address)) !== "";
  }
  if (facts.hosted) {
    return (facts.credential_keys ?? []).some((key) => isSet(key));
  }
  return text(effective(address)) !== "";
}

function llmStatus(
  effective: EffectiveValue,
  isSet: IsSet,
  schema?: SettingsSchema | null
): string {
  if (!llmLooksConfigured(effective, isSet, schema)) return "Not configured";
  const provider = text(effective(LLM_SELECTOR));
  const [expertKey, judgeKey] = choiceFacts(schema, LLM_SELECTOR, provider).model_keys ?? [
    `core.llm.${provider}.expert_model`,
    `core.llm.${provider}.judge_model`,
  ];
  const expert = text(effective(expertKey));
  const judge = text(effective(judgeKey));
  const parts = [llmProviderTitle(provider, schema)];
  parts.push(expert ? `expert ${expert}` : "no expert model");
  parts.push(judge ? `judge ${judge}` : "no judge model");
  return parts.join(" · ");
}

function agentStatus(effective: EffectiveValue): string {
  const custom = countEnabled(effective(AGENT_DEFINITIONS_KEY), (k) => BUILTIN_AGENTS.has(k));
  const profile = text(effective("core.agents.profile")) || "default";
  const head =
    custom === 0
      ? "No custom analysts"
      : `${custom} custom analyst${custom === 1 ? "" : "s"} enabled`;
  return `${head} · active profile ${profile}`;
}

/** The display phrase a catalog key's choice declares (`choice_labels`), or none. */
export type ChoiceLabel = (key: string, choice: string) => string | undefined;

function memoryStatus(effective: EffectiveValue, choiceLabel?: ChoiceLabel): string {
  const backend = text(effective("core.memory.backend")) || "memory";
  // The phrase the backend declares beside its id ("in-process"), if any.
  const label = choiceLabel?.("core.memory.backend", backend);
  const name = label ? `${backend} (${label})` : backend;
  // A backend with an endpoint declares it as `core.memory.<id>.url`; one
  // without (the in-process store) has no such key.
  const url = effective(`core.memory.${backend}.url`);
  if (url === undefined) return name;
  return `${name} · ${text(url) || "no URL set"}`;
}

function enrichmentStatus(effective: EffectiveValue, isSet: IsSet): string {
  if (effective("api.enrichment_enabled") !== true) return "Off";
  const keys: string[] = [];
  if (isSet("api.virustotal_api_key")) keys.push("VirusTotal");
  if (isSet("api.abuseipdb_api_key")) keys.push("AbuseIPDB");
  return `On · ${keys.length > 0 ? keys.join(", ") : "no keys set"}`;
}

/** The hub's one-line summary of what a guide's settings currently say. */
export function guideStatus(
  id: GuideId,
  effective: EffectiveValue,
  isSet: IsSet,
  choiceLabel?: ChoiceLabel,
  schema?: SettingsSchema | null
): string {
  switch (id) {
    case "llm":
      return llmStatus(effective, isSet, schema);
    case "static":
      return text(effective("core.static.provider")) || "none";
    case "sandbox": {
      const provider = text(effective("core.sandbox.provider")) || "mock";
      return provider === "mock" ? "mock (built-in fixtures)" : provider;
    }
    case "tool-server": {
      const count = countEnabled(effective("core.mcp.servers"));
      return count === 0 ? "No servers enabled" : `${count} server${count === 1 ? "" : "s"} enabled`;
    }
    case "agent":
      return agentStatus(effective);
    case "memory":
      return memoryStatus(effective, choiceLabel);
    case "enrichment":
      return enrichmentStatus(effective, isSet);
  }
}
