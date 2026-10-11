import { AGENT_DEFINITIONS_KEY } from "../configuration/agentStaging";
import {
  builtinServerKeys,
  catalogEntry,
  choiceDescription,
  choiceFacts,
  choiceTitle,
  LLM_SELECTOR,
  SANDBOX_SELECTOR,
  STATIC_SELECTOR,
} from "@/lib/providerFacts";
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
  /** Catalog keys this step's own component (`server-form`, `agent-form`,
   *  `profile-picker`, ...) stages directly, for the review step's "which
   *  keys belong to this guide" filter — unlike `keys`, these are never
   *  rendered by `StepFields`, so declaring one here does not put a second,
   *  redundant `FieldRow` on the page next to the component that already
   *  edits it. Without this, a guide whose steps are all components (nothing
   *  ever staged through `keys`) never marks anything "touched": its review
   *  step would show "Nothing to apply" and Apply would stay disabled no
   *  matter what the guide actually staged. */
  reviewKeys?: string[];
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
    | "virustotal"
    | "review";
  /** Which part of a `server-form` / `agent-form` the step draws. The step
   *  components normalise an unknown value to their first section, so a
   *  guide that names none still renders. */
  section?:
    | "connection"
    | "tools"
    | "agents"
    | "identity"
    | "prompt"
    | "model"
    | "resolve";
  /** A link the step body shows under its intro — the way out of a step
   *  whose prerequisite lives in another guide. */
  link?: { href: string; label: string };
  /** The reason Continue is blocked, or null when the step is complete. */
  canContinue?: (ctx: GuideContext) => string | null;
}

export interface GuideDef {
  id: GuideId;
  title: string;
  blurb: string;
  /** What a first run needs. The hub offers these alone until a model is
   *  connected, because none of the rest can be tested without one. */
  firstRun?: boolean;
  /** The console group these keys live in — every step links to it. */
  groupHref: string;
  /** Steps may depend on the choices made so far (the LLM provider decides
   *  which credential fields exist). */
  steps: (ctx: GuideContext) => GuideStep[];
}

/** The card copy for one choice of a provider selector: the title and the
 *  sentence the provider declares for itself, served on the selector's catalog
 *  entry. A choice that declares none still gets a card, under its own id. */
export function providerChoiceCopy(
  schema: SettingsSchema | null | undefined,
  selectorKey: string,
  choice: string
): { title: string; blurb: string } {
  return {
    title: choiceTitle(schema, selectorKey, choice),
    blurb: choiceDescription(schema, selectorKey, choice),
  };
}

function llmProvider(ctx: GuideContext): string {
  return String(ctx.effective("core.llm.provider") ?? "").trim();
}

const LLM_GUIDE: GuideDef = {
  id: "llm",
  firstRun: true,
  title: "Connect a language model",
  blurb: "Pick a provider, store its credentials, test the connection and choose the models the analysts and the judge run on.",
  groupHref: "/settings/configuration/models/llm",
  steps: (ctx) => {
    const provider = llmProvider(ctx);
    // The provider declares which of its settings the credentials step shows,
    // whether it is a hosted API, and what the connection test should add.
    const facts = choiceFacts(ctx.schema, LLM_SELECTOR, provider);
    const testIntro = "This also fetches the list of models the next step offers.";
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
          facts.hosted === false
            ? `Where the ${choiceTitle(ctx.schema, LLM_SELECTOR, provider)} server listens.`
            : "The key is stored on the server and never shown again.",
        keys: [...(facts.guide_keys ?? []), ...(facts.guide_advanced_keys ?? [])],
        advancedKeys: facts.guide_advanced_keys ?? [],
        // The provider may only be staged at this point, and these keys are
        // gated on the *stored* one; the guide has already narrowed them, so
        // it renders its own list rather than deferring to `applies_when`.
        respectAppliesWhen: false,
      },
      {
        id: "test",
        title: "Test the connection",
        intro: facts.probe_note ? `${testIntro} ${facts.probe_note}` : testIntro,
        probe: "llm",
        canContinue: (c) => (c.probeOk("llm") ? null : "run the connection test first"),
      },
      {
        id: "models",
        title: "Expert and judge models",
        intro: "The analysts run on the expert model; the judge writes the verdict.",
        keys: provider ? facts.model_keys ?? [] : [],
        respectAppliesWhen: false,
        canContinue: (c) => {
          const p = llmProvider(c);
          const expert = String(c.effective(`core.llm.${p}.expert_model`) ?? "").trim();
          return expert ? null : "pick an expert model";
        },
      },
      {
        id: "review",
        title: "Review and apply",
        component: "review",
      },
    ];
  },
};

/** Every catalog key under `prefix`, in schema order, minus the exclusions.
 *  A guide names a family of keys this way rather than listing them, so a
 *  key the backend adds to a provider block reaches the guide with it. */
function keysUnder(ctx: GuideContext, prefix: string, exclude: string[] = []): string[] {
  const groups = ctx.schema?.groups ?? [];
  return groups
    .flatMap((group) => group.entries)
    .map((entry) => entry.key)
    .filter((key) => key.startsWith(prefix) && !exclude.includes(key));
}

function text(ctx: GuideContext, key: string): string {
  return String(ctx.effective(key) ?? "").trim();
}

function stateHas(ctx: GuideContext, field: string): boolean {
  const value = ctx.state[field];
  return typeof value === "string" && value !== "";
}

const REVIEW_STEP: GuideStep = { id: "review", title: "Review and apply", component: "review" };

/* ------------------------------------------------------------------ static */

/** Whether an operator has enabled a tool server of their own: the generic
 *  static provider needs one, and the built-in servers (as core names them)
 *  do not count towards "there is a server to point at". */
function hasCustomServer(ctx: GuideContext): boolean {
  const servers = ctx.effective("core.mcp.servers");
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) return false;
  const builtin = builtinServerKeys(ctx.schema);
  return Object.entries(servers as Record<string, { enabled?: boolean }>).some(
    ([key, value]) => !builtin.has(key) && value?.enabled === true
  );
}

/** The keys of a provider's own settings block, and the ones its catalog
 *  entries fold under "Advanced". */
function providerKeys(
  ctx: GuideContext,
  prefix: string,
  exclude: string[] = []
): { keys: string[]; advanced: string[] } {
  const keys = keysUnder(ctx, prefix, exclude);
  return { keys, advanced: keys.filter((key) => catalogEntry(ctx.schema, key)?.advanced) };
}

const STATIC_GUIDE: GuideDef = {
  id: "static",
  firstRun: true,
  title: "Choose a static analyser",
  blurb: "Pick what the static analyst reverse-engineers with, fill in that tool's settings and test it.",
  groupHref: "/settings/configuration/tools/static",
  steps: (ctx) => {
    const provider = text(ctx, STATIC_SELECTOR);
    const facts = choiceFacts(ctx.schema, STATIC_SELECTOR, provider);
    const probe = facts.probe ?? undefined;
    // A provider that drives a server of the registry names one in its block.
    const serverKey = keysUnder(ctx, "core.static.").find((key) =>
      catalogEntry(ctx.schema, key)?.choices_from === "mcp_servers"
    );
    const generic =
      serverKey !== undefined &&
      (catalogEntry(ctx.schema, serverKey)?.applies_when?.[STATIC_SELECTOR] ?? []).includes(
        provider
      );
    const steps: GuideStep[] = [
      {
        id: "provider",
        title: "Choose an analyser",
        intro: "The static analyst reads the sample through this tool.",
        component: "provider-choice",
        canContinue: (c) => (text(c, "core.static.provider") ? null : "pick an analyser"),
      },
      {
        id: "fields",
        title: "Settings for this analyser",
        intro: facts.intro,
        keys: keysUnder(ctx, "core.static.", ["core.static.provider"]),
        respectAppliesWhen: true,
        link:
          generic && !hasCustomServer(ctx)
            ? { href: "/settings/setup/tool-server", label: "Add a tool server first" }
            : undefined,
        canContinue:
          generic && serverKey
            ? (c) => (text(c, serverKey) ? null : "pick a tool server")
            : undefined,
      },
    ];
    if (probe) {
      steps.push({
        id: "test",
        title: "Test the analyser",
        intro: "The test reaches the tool exactly the way an analysis does.",
        probe,
        canContinue: (c) => (c.probeOk(probe) ? null : "run the test first"),
      });
    }
    steps.push(REVIEW_STEP);
    return steps;
  },
};

/* ----------------------------------------------------------------- sandbox */

const SANDBOX_GUIDE: GuideDef = {
  id: "sandbox",
  firstRun: true,
  title: "Connect a sandbox",
  blurb: "Pick where samples are detonated, describe how to reach it and test the connection.",
  groupHref: "/settings/configuration/tools/sandbox",
  steps: (ctx) => {
    const provider = text(ctx, SANDBOX_SELECTOR);
    const steps: GuideStep[] = [
      {
        id: "provider",
        title: "Choose a sandbox",
        intro: "The dynamic analyst reads the report this sandbox produces.",
        component: "provider-choice",
        canContinue: (c) => (text(c, "core.sandbox.provider") ? null : "pick a sandbox"),
      },
    ];

    // Every provider reads its own block's keys, its own test and its own
    // introduction from the schema. A block edited by the described-API editor
    // is walked through its connection, submit, status and report calls.
    const facts = choiceFacts(ctx.schema, SANDBOX_SELECTOR, provider);
    const prefix = `core.sandbox.${provider}.`;
    const own = provider ? providerKeys(ctx, prefix) : { keys: [], advanced: [] };
    const described = own.keys.some(
      (key) => catalogEntry(ctx.schema, key)?.editor === "rest_sandbox"
    );
    const probe = facts.probe ?? undefined;
    // The leaves a provider declares for its guide, up front and folded; with
    // none declared, its whole block by each entry's own advanced flag.
    const declared =
      facts.guide_keys !== undefined || facts.guide_advanced_keys !== undefined
        ? {
            keys: [...(facts.guide_keys ?? []), ...(facts.guide_advanced_keys ?? [])],
            advanced: facts.guide_advanced_keys ?? [],
          }
        : own;
    if (provider && !described) {
      if (declared.keys.length > 0) {
        steps.push({
          id: "fields",
          title: `${choiceTitle(ctx.schema, SANDBOX_SELECTOR, provider)} settings`,
          intro: facts.intro,
          keys: declared.keys,
          advancedKeys: declared.advanced,
        });
      }
      if (probe) {
        steps.push({
          id: "test",
          title: "Test the connection",
          probe,
          canContinue: (c) => (c.probeOk(probe) ? null : "run the test first"),
        });
      }
    } else if (described) {
      steps.push(
        {
          id: "connection",
          title: "Connection",
          intro: "Where the sandbox API lives and how a request authenticates.",
          keys: [
            `${prefix}base_url`,
            `${prefix}auth.header`,
            `${prefix}auth.scheme`,
            `${prefix}auth.token`,
            `${prefix}verify_tls`,
            `${prefix}timeout_seconds`,
            `${prefix}poll_interval_seconds`,
          ],
        },
        {
          id: "submit",
          title: "Submit",
          intro: "The call that hands the sample over, and where the task id comes back.",
          keys: keysUnder(ctx, `${prefix}submit.`),
        },
        {
          id: "status",
          title: "Status",
          intro: "The call the poller repeats, and which states mean done or failed.",
          keys: keysUnder(ctx, `${prefix}status.`),
        },
        {
          id: "report",
          title: "Report",
          intro: "Where the finished report is fetched from, and what shape it arrives in.",
          keys: keysUnder(ctx, `${prefix}report.`),
        }
      );
      if (text(ctx, `${prefix}report.format`) === "generic") {
        steps.push({
          id: "mapping",
          title: "Report mapping",
          intro: "Paste a sample report and point each field at the path that holds it.",
          component: "rest-mapping",
        });
      }
      if (probe) {
        steps.push({
          id: "test",
          title: "Test the connection",
          probe,
          canContinue: (c) => (c.probeOk(probe) ? null : "run the test first"),
        });
      }
    }

    // A provider with nothing to fill in and nothing to test says what it is
    // where the operator would otherwise find an empty review.
    steps.push(
      provider && own.keys.length === 0 && !probe && facts.intro
        ? { ...REVIEW_STEP, intro: facts.intro }
        : REVIEW_STEP
    );
    return steps;
  },
};

/* ------------------------------------------------------------- tool server */

const TOOL_SERVER_GUIDE: GuideDef = {
  id: "tool-server",
  title: "Add a tool server",
  blurb: "Register an MCP server, load its tools and decide which analysts may call them.",
  groupHref: "/settings/configuration/tools/mcp",
  steps: () => [
    {
      // VirusTotal's server is the one tool server nobody has to stand up, so
      // it comes before the form that registers one by hand: an operator who
      // only wanted file and IP reputation is finished after this step.
      id: "virustotal",
      title: "Connect VirusTotal",
      intro:
        "VirusTotal runs its own MCP server. Register this deployment to get an agent token; " +
        "the token is stored encrypted here and the server is turned on with its lookups ticked.",
      component: "virustotal",
      reviewKeys: ["core.mcp.servers"],
    },
    {
      id: "which",
      title: "Which server",
      intro: "Add a new server, or open one that is already configured.",
      component: "server-form",
      section: "connection",
      reviewKeys: ["core.mcp.servers"],
      canContinue: (c) => (stateHas(c, "serverKey") ? null : "name or pick a server"),
    },
    {
      id: "connection",
      title: "Transport and connection",
      intro: "A stdio server is launched from a command; the others are reached over a URL.",
      component: "server-form",
      section: "connection",
    },
    {
      id: "tools",
      title: "Tools",
      intro: "Run Test to load the tools, then tick the ones the analysts may call. Keeping all tools is fine.",
      component: "server-form",
      section: "tools",
    },
    {
      id: "agents",
      title: "Analysts",
      intro: "Which analysts receive this server's tools.",
      component: "server-form",
      section: "agents",
    },
    REVIEW_STEP,
  ],
};

/* ------------------------------------------------------------------ agent */

const AGENT_GUIDE: GuideDef = {
  id: "agent",
  firstRun: true,
  title: "Create an analyst",
  blurb: "Clone a built-in analyst or start from a blank one, give it tools and a model, then add it to a stage.",
  groupHref: "/settings/configuration/agents/agents",
  steps: () => [
    {
      id: "start",
      title: "Start from",
      intro: "Clone a built-in analyst to inherit its prompt, or start from a blank generic one.",
      component: "agent-form",
      section: "identity",
      reviewKeys: [AGENT_DEFINITIONS_KEY, "core.llm.agents"],
      canContinue: (c) => (stateHas(c, "agentKey") ? null : "name the agent"),
    },
    {
      id: "prompt",
      title: "Prompt",
      intro: "Leave the prompt empty to keep the built-in one for this role.",
      component: "agent-form",
      section: "prompt",
    },
    {
      id: "tools",
      title: "Tools",
      intro: "Which servers and tools this analyst may call.",
      component: "agent-form",
      section: "tools",
    },
    {
      id: "model",
      title: "Model",
      intro: "Leave empty to run on the expert model the language-model settings name.",
      component: "agent-form",
      section: "model",
    },
    // Resolve stays last of the agent-form steps: visiting an earlier section
    // again clears `state.resolvedOk`, so a later step could never keep it.
    {
      id: "resolve",
      title: "Resolve",
      intro: "Resolve assembles the prompt, the model and the tools this analyst would run with.",
      component: "agent-form",
      section: "resolve",
      canContinue: (c) => (c.state.resolvedOk === true ? null : "run Resolve first"),
    },
    {
      id: "profile",
      title: "Add to a stage",
      intro: "An analyst runs only as one stage's member of one team.",
      component: "profile-picker",
      reviewKeys: ["core.agents.profiles", "core.agents.profile"],
    },
    REVIEW_STEP,
  ],
};

/* ----------------------------------------------------------------- memory */

/** The connection test a family of keys declares: the first `probe` any of
 *  their catalog entries names, or none. */
function probeOf(ctx: GuideContext, keys: string[]): string | undefined {
  const wanted = new Set(keys);
  return (
    (ctx.schema?.groups ?? [])
      .flatMap((group) => group.entries)
      .find((entry) => wanted.has(entry.key) && entry.probe)?.probe ?? undefined
  );
}

const MEMORY_GUIDE: GuideDef = {
  id: "memory",
  title: "Set up long-term memory",
  blurb: "Keep findings in process, or point Maljan at a store that survives a restart.",
  groupHref: "/settings/configuration/tools/memory",
  steps: (ctx) => {
    const steps: GuideStep[] = [
      {
        id: "backend",
        title: "Backend",
        intro:
          "In-process memory is emptied by a restart; a persistent backend keeps what earlier analyses learned.",
        keys: ["core.memory.backend"],
      },
    ];
    // Each backend's own settings are the catalog keys under its id; a
    // backend with none (the in-process one) has no connection to set up.
    const backend = text(ctx, "core.memory.backend");
    const own = backend ? keysUnder(ctx, `core.memory.${backend}.`) : [];
    if (own.length > 0) {
      const probe = probeOf(ctx, own);
      steps.push({
        id: "connection",
        title: "Connection",
        intro:
          "Where the store lives, what it keeps its cases in, and how many neighbours a lookup returns.",
        keys: [...own, "core.memory.top_k"],
      });
      if (probe) {
        steps.push({
          id: "test",
          title: "Test the connection",
          probe,
          canContinue: (c) => (c.probeOk(probe) ? null : "run the test first"),
        });
      }
    }
    steps.push(REVIEW_STEP);
    return steps;
  },
};

/* ------------------------------------------------------------- enrichment */

const ENRICHMENT_GUIDE: GuideDef = {
  id: "enrichment",
  title: "Enable threat-intelligence enrichment",
  blurb: "Look indicators up against VirusTotal and AbuseIPDB, within a per-analysis budget.",
  groupHref: "/settings/configuration/platform/enrichment",
  steps: () => [
    {
      id: "switch",
      title: "Enrichment and its budget",
      intro: "The budget caps how many lookups a single analysis may spend.",
      keys: ["api.enrichment_enabled", "api.enrichment_max_lookups"],
    },
    {
      id: "virustotal",
      title: "VirusTotal",
      intro: "Leave the key empty to skip VirusTotal. The key is stored on the server and never shown again.",
      keys: ["api.virustotal_api_key"],
      probe: "virustotal",
    },
    {
      id: "abuseipdb",
      title: "AbuseIPDB",
      intro: "Leave the key empty to skip AbuseIPDB. The key is stored on the server and never shown again.",
      keys: ["api.abuseipdb_api_key"],
      probe: "abuseipdb",
    },
    REVIEW_STEP,
  ],
};

/** The catalog key a guide's `provider-choice` step stages. Every guide that
 *  opens on a provider picker names its selector here. */
export const PROVIDER_CHOICE_KEY: Record<string, string> = {
  llm: "core.llm.provider",
  static: "core.static.provider",
  sandbox: "core.sandbox.provider",
};

/** The guides the hub offers, in the order an operator meets them. The hub
 *  and the console's "Set up with the guide" links both check membership
 *  here, so an id without a definition simply does not appear. */
export const GUIDES: GuideDef[] = [
  LLM_GUIDE,
  STATIC_GUIDE,
  SANDBOX_GUIDE,
  TOOL_SERVER_GUIDE,
  AGENT_GUIDE,
  MEMORY_GUIDE,
  ENRICHMENT_GUIDE,
];

export function guideById(id: string): GuideDef | undefined {
  return GUIDES.find((g) => g.id === id);
}

/** The guides on offer, narrowed to what a first run needs before a model is
 *  connected. Everything else is an improvement on a pipeline that already
 *  runs, and offering it first is offering somebody a choice they cannot
 *  evaluate. */
export function guidesFor(llmConfigured: boolean): GuideDef[] {
  return llmConfigured ? GUIDES : GUIDES.filter((g) => g.firstRun);
}
