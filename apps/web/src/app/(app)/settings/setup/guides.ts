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
  /** The console group these keys live in — every step links to it. */
  groupHref: string;
  /** Steps may depend on the choices made so far (the LLM provider decides
   *  which credential fields exist). */
  steps: (ctx: GuideContext) => GuideStep[];
}

/** The radio cards of a `provider-choice` step: a title and one plain
 *  sentence per choice, keyed by the catalog selector the step stages. A
 *  choice the catalog offers without an entry here still gets a card, under
 *  its own id and without a sentence. */
const PROVIDER_COPY: Record<string, Record<string, { title: string; blurb: string }>> = {
  "core.llm.provider": {
    openai: { title: "OpenAI", blurb: "Hosted OpenAI models or any OpenAI-compatible server" },
    anthropic: { title: "Anthropic", blurb: "Claude models via the Anthropic API" },
    gemini: { title: "Google Gemini", blurb: "Gemini models via Google AI" },
    ollama: { title: "Ollama", blurb: "Models running locally through Ollama" },
  },
  "core.static.provider": {
    none: {
      title: "No static analyser",
      blurb: "The static analyst works from the pre-extracted data only.",
    },
    ghidra: {
      title: "Ghidra MCP",
      blurb: "A running Ghidra MCP server decompiles and names functions on request.",
    },
    r2: {
      title: "radare2 MCP",
      blurb: "A local radare2 binary answers disassembly questions over its MCP server.",
    },
    capa_yara: {
      title: "capa + YARA",
      blurb: "Rule sets on disk name the capabilities and match the file; no server to run.",
    },
    generic_mcp: {
      title: "Generic MCP server",
      blurb: "A server from the tool-server registry supplies the static tools.",
    },
  },
  "core.sandbox.provider": {
    mock: {
      title: "Mock sandbox",
      blurb: "Built-in fixture reports stand in for a detonation; nothing is executed.",
    },
    cape2: {
      title: "CAPEv2",
      blurb: "A CAPEv2 instance detonates the sample and returns its report.",
    },
    upload: {
      title: "Uploaded report",
      blurb: "No detonation here: an operator attaches a report from another sandbox.",
    },
    triage: {
      title: "Hatching Triage",
      blurb: "Triage runs the sample in its cloud and returns the report it produced.",
    },
    rest: {
      title: "Generic REST API",
      blurb: "Any sandbox with an HTTP API, described by the paths the next steps fill in.",
    },
  },
};

/** The card copy for one choice of a provider selector. */
export function providerChoiceCopy(
  selectorKey: string,
  choice: string
): { title: string; blurb: string } {
  const copy = PROVIDER_COPY[selectorKey]?.[choice];
  return { title: copy?.title ?? choice, blurb: copy?.blurb ?? "" };
}

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

/** The connection test each static provider owns. A provider absent here has
 *  nothing to test, so the guide shows no test step for it. */
const STATIC_PROBE: Record<string, string> = {
  ghidra: "ghidra",
  r2: "r2",
  capa_yara: "capa_yara",
};

/** Server keys the backend pre-populates. The generic static provider needs
 *  one the operator added, so these do not count towards "there is a server
 *  to point at". */
const BUILTIN_SERVER_KEYS = new Set(["network", "threatintel"]);

function hasCustomServer(ctx: GuideContext): boolean {
  const servers = ctx.effective("core.mcp.servers");
  if (!servers || typeof servers !== "object" || Array.isArray(servers)) return false;
  return Object.entries(servers as Record<string, { enabled?: boolean }>).some(
    ([key, value]) => !BUILTIN_SERVER_KEYS.has(key) && value?.enabled === true
  );
}

const STATIC_FIELDS_INTRO: Record<string, string> = {
  none: "No static provider: the static analyst works from the pre-extracted data only.",
  ghidra: "Where the Ghidra MCP server listens, and how it authenticates.",
  r2: "Where the radare2 binary lives; the MCP server is launched from it.",
  capa_yara: "The rule directories to load. Both are read at the start of every analysis.",
  generic_mcp: "Which configured tool server drives the static analyst.",
};

const STATIC_GUIDE: GuideDef = {
  id: "static",
  title: "Choose a static analyser",
  blurb: "Pick what the static analyst reverse-engineers with, fill in that tool's settings and test it.",
  groupHref: "/settings/configuration/tools/static",
  steps: (ctx) => {
    const provider = text(ctx, "core.static.provider");
    const probe = STATIC_PROBE[provider];
    const generic = provider === "generic_mcp";
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
        intro: STATIC_FIELDS_INTRO[provider],
        keys: keysUnder(ctx, "core.static.", ["core.static.provider"]),
        respectAppliesWhen: true,
        link:
          generic && !hasCustomServer(ctx)
            ? { href: "/settings/setup/tool-server", label: "Add a tool server first" }
            : undefined,
        canContinue: generic
          ? (c) => (text(c, "core.static.generic.server") ? null : "pick a tool server")
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
  title: "Connect a sandbox",
  blurb: "Pick where samples are detonated, describe how to reach it and test the connection.",
  groupHref: "/settings/configuration/tools/sandbox",
  steps: (ctx) => {
    const provider = text(ctx, "core.sandbox.provider");
    const steps: GuideStep[] = [
      {
        id: "provider",
        title: "Choose a sandbox",
        intro: "The dynamic analyst reads the report this sandbox produces.",
        component: "provider-choice",
        canContinue: (c) => (text(c, "core.sandbox.provider") ? null : "pick a sandbox"),
      },
    ];

    if (provider === "cape2") {
      const mcpKeys = keysUnder(ctx, "core.sandbox.cape2.mcp.");
      steps.push(
        {
          id: "fields",
          title: "CAPE connection",
          intro: "The API token is stored on the server and never shown again.",
          keys: [
            "core.sandbox.cape2.api_token",
            "core.sandbox.cape2.base_url",
            "core.sandbox.cape2.poll_interval_seconds",
            "core.sandbox.cape2.timeout_seconds",
            ...mcpKeys,
          ],
          advancedKeys: mcpKeys,
        },
        {
          id: "test",
          title: "Test the connection",
          probe: "cape2",
          canContinue: (c) => (c.probeOk("cape2") ? null : "run the test first"),
        }
      );
    } else if (provider === "triage") {
      steps.push(
        {
          id: "fields",
          title: "Triage connection",
          intro: "The API token is stored on the server and never shown again.",
          keys: [
            "core.sandbox.triage.api_token",
            "core.sandbox.triage.base_url",
            "core.sandbox.triage.profile",
            "core.sandbox.triage.fetch_pcap",
            "core.sandbox.triage.poll_interval_seconds",
            "core.sandbox.triage.timeout_seconds",
          ],
        },
        {
          id: "test",
          title: "Test the connection",
          probe: "triage",
          canContinue: (c) => (c.probeOk("triage") ? null : "run the test first"),
        }
      );
    } else if (provider === "upload") {
      steps.push({
        id: "fields",
        title: "Uploaded reports",
        intro: "Which report formats an operator may attach, and how large they may be.",
        keys: ["core.sandbox.upload.allowed_formats", "core.sandbox.upload.max_report_bytes"],
      });
    } else if (provider === "rest") {
      steps.push(
        {
          id: "connection",
          title: "Connection",
          intro: "Where the sandbox API lives and how a request authenticates.",
          keys: [
            "core.sandbox.rest.base_url",
            "core.sandbox.rest.auth.header",
            "core.sandbox.rest.auth.scheme",
            "core.sandbox.rest.auth.token",
            "core.sandbox.rest.verify_tls",
            "core.sandbox.rest.timeout_seconds",
            "core.sandbox.rest.poll_interval_seconds",
          ],
        },
        {
          id: "submit",
          title: "Submit",
          intro: "The call that hands the sample over, and where the task id comes back.",
          keys: keysUnder(ctx, "core.sandbox.rest.submit."),
        },
        {
          id: "status",
          title: "Status",
          intro: "The call the poller repeats, and which states mean done or failed.",
          keys: keysUnder(ctx, "core.sandbox.rest.status."),
        },
        {
          id: "report",
          title: "Report",
          intro: "Where the finished report is fetched from, and what shape it arrives in.",
          keys: keysUnder(ctx, "core.sandbox.rest.report."),
        }
      );
      if (text(ctx, "core.sandbox.rest.report.format") === "generic") {
        steps.push({
          id: "mapping",
          title: "Report mapping",
          intro: "Paste a sample report and point each field at the path that holds it.",
          component: "rest-mapping",
        });
      }
      steps.push({
        id: "test",
        title: "Test the connection",
        probe: "rest",
        canContinue: (c) => (c.probeOk("rest") ? null : "run the test first"),
      });
    }

    steps.push(
      provider === "mock"
        ? {
            ...REVIEW_STEP,
            intro: "Mock sandbox: built-in fixture reports stand in for a detonation.",
          }
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
      id: "which",
      title: "Which server",
      intro: "Add a new server, or open one that is already configured.",
      component: "server-form",
      section: "connection",
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
  title: "Create an analyst",
  blurb: "Clone a built-in analyst or start from a blank one, give it tools and a model, then add it to a profile.",
  groupHref: "/settings/configuration/agents/agents",
  steps: () => [
    {
      id: "start",
      title: "Start from",
      intro: "Clone a built-in analyst to inherit its prompt, or start from a blank generic one.",
      component: "agent-form",
      section: "identity",
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
      title: "Add to a profile",
      intro: "An analyst runs only as part of a profile.",
      component: "profile-picker",
    },
    REVIEW_STEP,
  ],
};

/* ----------------------------------------------------------------- memory */

const MEMORY_GUIDE: GuideDef = {
  id: "memory",
  title: "Set up long-term memory",
  blurb: "Keep findings in process, or point Maljan at a Qdrant instance that survives a restart.",
  groupHref: "/settings/configuration/tools/memory",
  steps: (ctx) => {
    const steps: GuideStep[] = [
      {
        id: "backend",
        title: "Backend",
        intro: "In-process memory is emptied by a restart; Qdrant keeps what earlier analyses learned.",
        keys: ["core.memory.backend"],
      },
    ];
    if (text(ctx, "core.memory.backend") === "qdrant") {
      steps.push(
        {
          id: "qdrant",
          title: "Qdrant connection",
          intro: "Where the instance lives, which collections to use, and how many neighbours a lookup returns.",
          keys: [
            "core.memory.qdrant_url",
            "core.memory.qdrant_api_key",
            "core.memory.qdrant_collection",
            "core.memory.qdrant_function_hash_collection",
            "core.memory.top_k",
          ],
        },
        {
          id: "test",
          title: "Test the connection",
          probe: "qdrant",
          canContinue: (c) => (c.probeOk("qdrant") ? null : "run the test first"),
        }
      );
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
