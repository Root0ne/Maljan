import type { SettingsSchema } from "@/types/settings";

export type GuideId =
  | "llm"
  | "static"
  | "sandbox"
  | "tool-server"
  | "agent"
  | "memory"
  | "enrichment";

/** What a step's `canContinue` and a guide's `steps` may look at. Everything
 *  here comes from the shared settings context except `state`, the guide
 *  page's own scratch object (a selected server key, a clone source) that no
 *  catalog key holds. */
export interface GuideContext {
  effective: (key: string) => unknown;
  staged: Record<string, unknown>;
  probeOk: (probeId: string) => boolean;
  schema: SettingsSchema;
  state: Record<string, unknown>;
}

export interface GuideStep {
  /** Route query `?step=<id>`. */
  id: string;
  title: string;
  intro?: string;
  /** Catalog keys rendered with `FieldRow variant="guide"`. */
  keys?: string[];
  /** Default true: a key hidden by its `applies_when` is skipped. A guide
   *  that has already narrowed the provider itself sets this false so the
   *  step still renders while the selector is only staged. */
  respectAppliesWhen?: boolean;
  /** Probe id whose button and result this step shows. */
  probe?: string;
  /** Keys of `keys` that belong under the step's "Advanced" disclosure, on
   *  top of the ones the catalog already marks advanced. */
  advancedKeys?: string[];
  component?:
    | "server-form"
    | "agent-form"
    | "profile-picker"
    | "rest-mapping"
    | "provider-choice"
    | "review";
  /** The reason Continue is blocked, or null when the step is complete. */
  canContinue?: (ctx: GuideContext) => string | null;
}

export interface GuideDef {
  id: GuideId;
  title: string;
  blurb: string;
  /** The console group these keys live in — every step links to it. */
  groupHref: string;
  /** Steps may depend on the choices made so far (the LLM provider decides
   *  which credential fields exist). */
  steps: (ctx: GuideContext) => GuideStep[];
}

/** One line per language-model provider, shown on the radio cards of the
 *  `provider-choice` step. A choice the catalog offers without a line here
 *  still gets a card, just without the sentence. */
export const LLM_PROVIDER_BLURB: Record<string, string> = {
  openai: "Hosted OpenAI models or any OpenAI-compatible server",
  anthropic: "Claude models via the Anthropic API",
  gemini: "Gemini models via Google AI",
  ollama: "Models running locally through Ollama",
};

export const LLM_PROVIDER_TITLE: Record<string, string> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
  gemini: "Google Gemini",
  ollama: "Ollama",
};

/** Credential and endpoint keys per provider, and which of them are folded
 *  away. Only the selected provider's keys are ever rendered. */
const CREDENTIAL_KEYS: Record<string, { keys: string[]; advanced: string[] }> = {
  openai: {
    keys: [
      "core.llm.openai.api_key",
      "core.llm.openai.base_url",
      "core.llm.openai.disable_thinking",
      "core.llm.openai.repetition_penalty",
    ],
    advanced: ["core.llm.openai.disable_thinking", "core.llm.openai.repetition_penalty"],
  },
  anthropic: { keys: ["core.llm.anthropic.api_key"], advanced: [] },
  gemini: { keys: ["core.llm.gemini.api_key"], advanced: [] },
  ollama: {
    keys: ["core.llm.ollama.base_url", "core.llm.ollama.num_ctx", "core.llm.ollama.keep_alive"],
    advanced: ["core.llm.ollama.num_ctx", "core.llm.ollama.keep_alive"],
  },
};

function llmProvider(ctx: GuideContext): string {
  return String(ctx.effective("core.llm.provider") ?? "").trim();
}

const LLM_GUIDE: GuideDef = {
  id: "llm",
  title: "Connect a language model",
  blurb: "Pick a provider, store its credentials, test the connection and choose the models the analysts and the judge run on.",
  groupHref: "/settings/configuration/models/llm",
  steps: (ctx) => {
    const provider = llmProvider(ctx);
    const credentials = CREDENTIAL_KEYS[provider] ?? { keys: [], advanced: [] };
    return [
      {
        id: "provider",
        title: "Choose a provider",
        intro: "Every analyst and the judge talk to this provider.",
        component: "provider-choice",
        canContinue: (c) => (llmProvider(c) ? null : "pick a provider"),
      },
      {
        id: "credentials",
        title: "Credentials and endpoint",
        intro:
          provider === "ollama"
            ? "Where the local Ollama server listens."
            : "The key is stored on the server and never shown again.",
        keys: credentials.keys,
        advancedKeys: credentials.advanced,
        // The provider may only be staged at this point, and these keys are
        // gated on the *stored* one; the guide has already narrowed them, so
        // it renders its own list rather than deferring to `applies_when`.
        respectAppliesWhen: false,
      },
      {
        id: "test",
        title: "Test the connection",
        intro: "This also fetches the list of models the next step offers.",
        probe: "llm",
        canContinue: (c) => (c.probeOk("llm") ? null : "run the connection test first"),
      },
      {
        id: "models",
        title: "Expert and judge models",
        intro: "The analysts run on the expert model; the judge writes the verdict.",
        keys: provider
          ? [`core.llm.${provider}.expert_model`, `core.llm.${provider}.judge_model`]
          : [],
        respectAppliesWhen: false,
        canContinue: (c) => {
          const p = llmProvider(c);
          const expert = String(c.effective(`core.llm.${p}.expert_model`) ?? "").trim();
          return expert ? null : "pick an expert model";
        },
      },
      {
        id: "limits",
        title: "Limits",
        intro: "Token budgets and how many analysts run at once. The defaults are fine to keep.",
        keys: [
          "core.llm.expert_max_tokens",
          "core.llm.judge_max_tokens",
          "core.llm.parallel_analysts",
          "core.llm.view_decomposition_mode",
          "core.llm.view_decomposition_views",
        ],
      },
      {
        id: "review",
        title: "Review and apply",
        component: "review",
      },
    ];
  },
};

/** The catalog key a guide's `provider-choice` step stages. Every guide that
 *  opens on a provider picker names its selector here. */
export const PROVIDER_CHOICE_KEY: Record<string, string> = {
  llm: "core.llm.provider",
  static: "core.static.provider",
  sandbox: "core.sandbox.provider",
};

/** The guides the hub offers. The remaining six arrive with Task 18; the hub
 *  and the console's "Set up with the guide" links both check membership
 *  here, so an id without a definition simply does not appear. */
export const GUIDES: GuideDef[] = [LLM_GUIDE];

export function guideById(id: string): GuideDef | undefined {
  return GUIDES.find((g) => g.id === id);
}
