import type { GuideId } from "./guides";

/** Reads the value a key currently has — staged if it is staged, else stored.
 *  Exactly `SettingsContextValue.effectiveValue`. */
export type EffectiveValue = (key: string) => unknown;

/** Whether a secret key has a value stored on the server. A secret's value
 *  never travels, so `effective` cannot answer this: `values[key].is_set`
 *  does. */
export type IsSet = (key: string) => boolean;

/** The providers that authenticate with a key rather than a local endpoint. */
const HOSTED_PROVIDERS = new Set(["openai", "anthropic", "gemini"]);

/** The flat catalog keys that hold the same credential as
 *  `core.llm.<provider>.api_key`: an operator who filled one of these in has
 *  configured that provider just as much as one who filled in the namespaced
 *  leaf, and the hub must not go on calling it unconfigured. */
const FLAT_API_KEY: Record<string, string> = {
  openai: "core.openai_api_key",
  anthropic: "core.anthropic_api_key",
  gemini: "core.google_api_key",
};

const PROVIDER_TITLE: Record<string, string> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
  gemini: "Google Gemini",
  ollama: "Ollama",
};

export function llmProviderTitle(provider: string): string {
  return PROVIDER_TITLE[provider] ?? provider;
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
 *  custom analyst. Duplicated from `AgentDefinitionsEditor.BUILTIN_AGENT_KEYS`
 *  rather than imported so this module stays free of React imports (it is
 *  unit-tested on its own). */
const BUILTIN_AGENTS = new Set(["static", "dynamic", "network", "judge"]);

/**
 * Whether the language-model settings could plausibly run an analysis: a
 * hosted provider with its API key stored, or Ollama with a base URL. Decides
 * whether `/settings/configuration` lands on the console or on the guide hub.
 */
export function llmLooksConfigured(effective: EffectiveValue, isSet: IsSet): boolean {
  const provider = text(effective("core.llm.provider"));
  if (!provider) return false;
  if (HOSTED_PROVIDERS.has(provider)) {
    const flat = FLAT_API_KEY[provider];
    return isSet(`core.llm.${provider}.api_key`) || (flat !== undefined && isSet(flat));
  }
  return text(effective(`core.llm.${provider}.base_url`)) !== "";
}

function llmStatus(effective: EffectiveValue, isSet: IsSet): string {
  if (!llmLooksConfigured(effective, isSet)) return "Not configured";
  const provider = text(effective("core.llm.provider"));
  const expert = text(effective(`core.llm.${provider}.expert_model`));
  const judge = text(effective(`core.llm.${provider}.judge_model`));
  const parts = [llmProviderTitle(provider)];
  parts.push(expert ? `expert ${expert}` : "no expert model");
  parts.push(judge ? `judge ${judge}` : "no judge model");
  return parts.join(" · ");
}

function agentStatus(effective: EffectiveValue): string {
  const custom = countEnabled(effective("core.agents.definitions"), (k) => BUILTIN_AGENTS.has(k));
  const profile = text(effective("core.agents.profile")) || "default";
  const head =
    custom === 0
      ? "No custom analysts"
      : `${custom} custom analyst${custom === 1 ? "" : "s"} enabled`;
  return `${head} · active profile ${profile}`;
}

function memoryStatus(effective: EffectiveValue): string {
  const backend = text(effective("core.memory.backend")) || "memory";
  if (backend !== "qdrant") return "memory (in-process)";
  const url = text(effective("core.memory.qdrant_url"));
  return `qdrant · ${url || "no URL set"}`;
}

function enrichmentStatus(effective: EffectiveValue, isSet: IsSet): string {
  if (effective("api.enrichment_enabled") !== true) return "Off";
  const keys: string[] = [];
  if (isSet("api.virustotal_api_key")) keys.push("VirusTotal");
  if (isSet("api.abuseipdb_api_key")) keys.push("AbuseIPDB");
  return `On · ${keys.length > 0 ? keys.join(", ") : "no keys set"}`;
}

/** The hub's one-line summary of what a guide's settings currently say. */
export function guideStatus(id: GuideId, effective: EffectiveValue, isSet: IsSet): string {
  switch (id) {
    case "llm":
      return llmStatus(effective, isSet);
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
      return memoryStatus(effective);
    case "enrichment":
      return enrichmentStatus(effective, isSet);
  }
}
