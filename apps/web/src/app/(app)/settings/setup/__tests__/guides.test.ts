import { describe, expect, it } from "vitest";
import type { CatalogEntry, SettingsSchema } from "@/types/settings";
import { GUIDES, guideById, providerChoiceCopy, type GuideContext } from "../guides";

/**
 * The guides are pure functions of a `GuideContext`, so they can be walked
 * without React: this builds a context by hand, per branch, and asserts the
 * step order and the reasons Continue is blocked.
 */

const entry = (key: string): CatalogEntry => ({
  key,
  namespace: key.startsWith("api.") ? "api" : "core",
  path: key.slice(key.indexOf(".") + 1),
  type: "str",
  default: "",
  nullable: false,
  choices: null,
  minimum: null,
  maximum: null,
  secret: false,
  group: key.split(".")[1] ?? "",
  title: key,
  description: "",
  applies: "next_job",
  editable: true,
  reason: null,
  probe: null,
  applies_when: null,
  order: 0,
  choices_from: null,
  editor: null,
  subgroup: null,
  advanced: false,
  required_env: null,
});

/** Enough of the catalog for the guides that name key families by prefix. */
const KEYS = [
  "core.static.provider",
  "core.static.r2.binary_path",
  "core.static.r2.mirror_dir",
  "core.static.capa.rules_dir",
  "core.static.yara.rules_dir",
  "core.static.generic.server",
  "core.sandbox.provider",
  "core.sandbox.cape2.base_url",
  "core.sandbox.cape2.api_token",
  "core.sandbox.cape2.mcp.enabled",
  "core.sandbox.cape2.mcp.url",
  "core.sandbox.triage.api_token",
  "core.sandbox.upload.allowed_formats",
  "core.sandbox.rest.base_url",
  "core.sandbox.rest.submit.method",
  "core.sandbox.rest.submit.path",
  "core.sandbox.rest.status.path",
  "core.sandbox.rest.report.path",
  "core.sandbox.rest.report.format",
  "core.memory.backend",
  "core.memory.qdrant.url",
  "core.memory.qdrant.api_key",
  "core.memory.vectorhub.endpoint",
  "core.memory.top_k",
];

/** The probe each catalog entry declares, as the catalogue annotations do. */
const PROBES: Record<string, string> = {
  "core.memory.qdrant.url": "qdrant",
};

/** What the API serves on each provider selector and on the server map: the
 *  providers' own declarations, as `provider_facts` gathers them. */
const ANTHROPIC_LEAVES = [
  "api_key",
  "base_url",
  "allow_plain_http_to_docker_host",
  "effort",
  "prompt_cache_ttl",
];
const SERVED: Record<string, Partial<CatalogEntry>> = {
  "core.llm.provider": {
    choices: ["openai", "anthropic", "ollama", "gemini"],
    choice_titles: {
      openai: "OpenAI",
      anthropic: "Anthropic",
      ollama: "Ollama",
      gemini: "Google Gemini",
    },
    choice_descriptions: {
      openai: "Hosted OpenAI models or any OpenAI-compatible server",
      anthropic: "Claude models via the Anthropic API",
      ollama: "Models running locally through Ollama",
      gemini: "Gemini models via Google AI",
    },
    choice_facts: {
      anthropic: {
        hosted: true,
        guide_keys: ANTHROPIC_LEAVES.map((leaf) => `core.llm.anthropic.${leaf}`),
        guide_advanced_keys: ANTHROPIC_LEAVES.slice(1).map((leaf) => `core.llm.anthropic.${leaf}`),
        model_keys: ["core.llm.anthropic.expert_model", "core.llm.anthropic.judge_model"],
        probe: "llm",
      },
    },
  },
  "core.static.provider": {
    choices: ["none", "ghidra", "r2", "capa_yara", "generic_mcp"],
    choice_titles: {
      none: "No static analyser",
      ghidra: "Ghidra MCP",
      r2: "radare2 MCP",
      capa_yara: "capa + YARA",
      generic_mcp: "Generic MCP server",
    },
    choice_descriptions: {
      none: "The static analyst works from the pre-extracted data only.",
      ghidra: "A running Ghidra MCP server decompiles and names functions on request.",
      r2: "A local radare2 binary answers disassembly questions over its MCP server.",
      capa_yara: "Rule sets on disk name the capabilities and match the file.",
      generic_mcp: "A server from the tool-server registry supplies the static tools.",
    },
    choice_facts: {
      none: { probe: null, intro: "No static provider." },
      ghidra: { probe: "ghidra", intro: "Where the Ghidra MCP server listens." },
      r2: { probe: "r2", intro: "Where the radare2 binary lives." },
      capa_yara: { probe: "capa_yara", intro: "The rule directories to load." },
      generic_mcp: { probe: null, intro: "Which configured tool server drives the analyst." },
    },
  },
  "core.static.generic.server": {
    choices_from: "mcp_servers",
    applies_when: { "core.static.provider": ["generic_mcp"] },
  },
  "core.sandbox.provider": {
    choices: ["mock", "cape2", "upload", "triage", "rest"],
    choice_titles: {
      mock: "Mock sandbox",
      cape2: "CAPEv2",
      upload: "Uploaded report",
      triage: "Hatching Triage",
      rest: "Generic REST API",
    },
    choice_descriptions: {
      mock: "Built-in fixture reports stand in for a detonation; nothing is executed.",
      cape2: "A CAPEv2 instance detonates the sample and returns its report.",
      upload: "No detonation here: an operator attaches a report from another sandbox.",
      triage: "Triage runs the sample in its cloud and returns the report it produced.",
      rest: "Any sandbox with an HTTP API, described by the paths the next steps fill in.",
    },
    choice_facts: {
      mock: { probe: null, intro: "Mock sandbox: built-in fixture reports stand in." },
      cape2: { probe: "cape2", intro: "The API token is stored on the server." },
      upload: { probe: null, intro: "Which report formats an operator may attach." },
      triage: { probe: "triage", intro: "The API token is stored on the server." },
      rest: { probe: "rest", intro: "Where the sandbox API lives." },
    },
  },
  "core.sandbox.cape2.mcp.enabled": { advanced: true },
  "core.sandbox.cape2.mcp.url": { advanced: true },
  "core.mcp.servers": {
    editor: "server_map",
    builtin_servers: ["analysis", "knowledge", "network", "threatintel", "virustotal"],
    reserved_servers: ["analysis", "knowledge", "network", "threatintel", "virustotal"],
  },
};

const schema: SettingsSchema = {
  groups: [
    {
      key: "all",
      title: "All",
      description: "",
      entries: [...KEYS, "core.llm.provider", "core.mcp.servers"].map((key) => ({
        ...entry(key),
        probe: PROBES[key] ?? null,
        ...(key.startsWith("core.sandbox.rest.") ? { editor: "rest_sandbox" } : {}),
        ...(SERVED[key] ?? {}),
      })) as CatalogEntry[],
    },
  ],
};

function context(
  values: Record<string, unknown> = {},
  options: { probes?: string[]; state?: Record<string, unknown> } = {}
): GuideContext {
  return {
    effective: (key: string) => values[key],
    staged: {},
    probeOk: (probeId: string) => (options.probes ?? []).includes(probeId),
    schema,
    state: options.state ?? {},
  };
}

function stepIds(id: string, ctx: GuideContext): string[] {
  const guide = guideById(id);
  if (!guide) throw new Error(`no guide ${id}`);
  return guide.steps(ctx).map((s) => s.id);
}

function blockedReason(id: string, stepId: string, ctx: GuideContext): string | null {
  const guide = guideById(id);
  if (!guide) throw new Error(`no guide ${id}`);
  const step = guide.steps(ctx).find((s) => s.id === stepId);
  if (!step) throw new Error(`no step ${stepId} in ${id}`);
  return step.canContinue?.(ctx) ?? null;
}

describe("the guide list", () => {
  it("offers all seven ids, each with a blurb and a console group", () => {
    expect(GUIDES.map((g) => g.id)).toEqual([
      "llm",
      "static",
      "sandbox",
      "tool-server",
      "agent",
      "memory",
      "enrichment",
    ]);
    for (const guide of GUIDES) {
      expect(guide.blurb.length).toBeGreaterThan(10);
      expect(guide.groupHref.startsWith("/settings/configuration/")).toBe(true);
      // Every guide ends on the review step the page's Apply button needs.
      expect(guide.steps(context()).at(-1)?.component).toBe("review");
    }
  });

  it("gives every provider choice of a picker guide a title and a line", () => {
    for (const [key, choices] of [
      ["core.llm.provider", ["openai", "anthropic", "gemini", "ollama"]],
      ["core.static.provider", ["none", "ghidra", "r2", "capa_yara", "generic_mcp"]],
      ["core.sandbox.provider", ["mock", "cape2", "upload", "triage", "rest"]],
    ] as const) {
      for (const choice of choices) {
        const copy = providerChoiceCopy(schema, key, choice);
        expect(copy.title).not.toBe(choice);
        expect(copy.blurb.length).toBeGreaterThan(10);
      }
    }
    // An unknown choice still gets a card, under its own id.
    expect(providerChoiceCopy(schema, "core.static.provider", "future")).toEqual({
      title: "future",
      blurb: "",
    });
  });
});

describe("the static guide", () => {
  it("shows the provider's own test, and none for the choices that have none", () => {
    const of = (provider: string) =>
      stepIds("static", context({ "core.static.provider": provider }));
    expect(of("r2")).toEqual(["provider", "fields", "test", "review"]);
    expect(of("ghidra")).toEqual(["provider", "fields", "test", "review"]);
    expect(of("capa_yara")).toEqual(["provider", "fields", "test", "review"]);
    expect(of("none")).toEqual(["provider", "fields", "review"]);
    expect(of("generic_mcp")).toEqual(["provider", "fields", "review"]);
  });

  it("blocks until a provider is picked", () => {
    expect(blockedReason("static", "provider", context())).toBe("pick an analyser");
    expect(
      blockedReason("static", "provider", context({ "core.static.provider": "r2" }))
    ).toBeNull();
  });

  it("blocks the test step until the probe has passed", () => {
    const values = { "core.static.provider": "r2" };
    expect(blockedReason("static", "test", context(values))).toBe("run the test first");
    expect(blockedReason("static", "test", context(values, { probes: ["r2"] }))).toBeNull();
    // Another provider's passing probe does not unblock this one.
    expect(blockedReason("static", "test", context(values, { probes: ["ghidra"] }))).toBe(
      "run the test first"
    );
  });

  it("offers only the chosen provider's rows, and defers the rest to applies_when", () => {
    const guide = guideById("static")!;
    const fields = guide.steps(context({ "core.static.provider": "r2" }))[1];
    expect(fields.respectAppliesWhen).toBe(true);
    expect(fields.keys).not.toContain("core.static.provider");
    expect(fields.keys).toContain("core.static.r2.binary_path");
    expect(fields.keys).toContain("core.static.capa.rules_dir");
  });

  it("sends the generic provider to the tool-server guide until a server exists", () => {
    const values: Record<string, unknown> = { "core.static.provider": "generic_mcp" };
    const empty = guideById("static")!.steps(context(values))[1];
    expect(empty.link?.href).toBe("/settings/setup/tool-server");
    expect(blockedReason("static", "fields", context(values))).toBe("pick a tool server");

    // A pre-populated built-in is not a server the operator can point at.
    const builtinOnly = { ...values, "core.mcp.servers": { network: { enabled: true } } };
    expect(guideById("static")!.steps(context(builtinOnly))[1].link).toBeDefined();

    const withServer = {
      ...values,
      "core.mcp.servers": { mine: { enabled: true } },
      "core.static.generic.server": "mine",
    };
    expect(guideById("static")!.steps(context(withServer))[1].link).toBeUndefined();
    expect(blockedReason("static", "fields", context(withServer))).toBeNull();
  });
});

describe("the sandbox guide", () => {
  it("walks the REST provider through its four calls and its mapping", () => {
    const rest = { "core.sandbox.provider": "rest" };
    expect(stepIds("sandbox", context(rest))).toEqual([
      "provider",
      "connection",
      "submit",
      "status",
      "report",
      "test",
      "review",
    ]);
    expect(
      stepIds("sandbox", context({ ...rest, "core.sandbox.rest.report.format": "generic" }))
    ).toEqual(["provider", "connection", "submit", "status", "report", "mapping", "test", "review"]);
  });

  it("gives each hosted sandbox its fields and its own probe", () => {
    expect(stepIds("sandbox", context({ "core.sandbox.provider": "cape2" }))).toEqual([
      "provider",
      "fields",
      "test",
      "review",
    ]);
    expect(stepIds("sandbox", context({ "core.sandbox.provider": "triage" }))).toEqual([
      "provider",
      "fields",
      "test",
      "review",
    ]);
    expect(stepIds("sandbox", context({ "core.sandbox.provider": "upload" }))).toEqual([
      "provider",
      "fields",
      "review",
    ]);
    expect(stepIds("sandbox", context({ "core.sandbox.provider": "mock" }))).toEqual([
      "provider",
      "review",
    ]);
  });

  it("folds the CAPE MCP sidecar away and blocks on the CAPE probe", () => {
    const values = { "core.sandbox.provider": "cape2" };
    const fields = guideById("sandbox")!.steps(context(values))[1];
    expect(fields.keys).toContain("core.sandbox.cape2.api_token");
    expect(fields.advancedKeys).toEqual([
      "core.sandbox.cape2.mcp.enabled",
      "core.sandbox.cape2.mcp.url",
    ]);
    expect(blockedReason("sandbox", "test", context(values))).toBe("run the test first");
    expect(blockedReason("sandbox", "test", context(values, { probes: ["cape2"] }))).toBeNull();
  });

  it("says what the mock sandbox does instead of leaving the review bare", () => {
    const review = guideById("sandbox")!
      .steps(context({ "core.sandbox.provider": "mock" }))
      .at(-1);
    expect(review?.intro).toContain("fixture reports");
  });
});

describe("the tool-server guide", () => {
  it("offers VirusTotal first, then asks which server before it shows any field", () => {
    expect(stepIds("tool-server", context())).toEqual([
      "virustotal",
      "which",
      "connection",
      "tools",
      "agents",
      "review",
    ]);
    expect(blockedReason("tool-server", "which", context())).toBe("name or pick a server");
    expect(
      blockedReason("tool-server", "which", context({}, { state: { serverKey: "mine" } }))
    ).toBeNull();
  });

  it("lets the tools step continue without a loaded manifest", () => {
    const state = { serverKey: "mine" };
    expect(blockedReason("tool-server", "tools", context({}, { state }))).toBeNull();
  });

  it("never blocks on the VirusTotal step, which is optional", () => {
    // Registering is one way to get a tool server, not a prerequisite for
    // adding one by hand, so Continue must pass straight through it.
    expect(blockedReason("tool-server", "virustotal", context())).toBeNull();
  });

  it("stages the server map through the VirusTotal step's review keys", () => {
    const step = guideById("tool-server")!
      .steps(context())
      .find((s) => s.id === "virustotal");
    expect(step?.component).toBe("virustotal");
    expect(step?.reviewKeys).toContain("core.mcp.servers");
  });
});

describe("the agent guide", () => {
  it("names the agent first and resolves it last", () => {
    expect(stepIds("agent", context())).toEqual([
      "start",
      "prompt",
      "tools",
      "model",
      "resolve",
      "profile",
      "review",
    ]);
    expect(blockedReason("agent", "start", context())).toBe("name the agent");
    expect(
      blockedReason("agent", "start", context({}, { state: { agentKey: "mine" } }))
    ).toBeNull();
  });

  it("blocks the resolve step until Resolve has answered", () => {
    const notYet = context({}, { state: { agentKey: "mine", resolvedOk: false } });
    expect(blockedReason("agent", "resolve", notYet)).toBe("run Resolve first");
    const resolved = context({}, { state: { agentKey: "mine", resolvedOk: true } });
    expect(blockedReason("agent", "resolve", resolved)).toBeNull();
  });
});

describe("the memory guide", () => {
  it("asks a backend with no keys of its own for nothing more", () => {
    expect(stepIds("memory", context({ "core.memory.backend": "memory" }))).toEqual([
      "backend",
      "review",
    ]);
  });

  it("asks for the keys under the backend's id and tests with the probe they declare", () => {
    const qdrant = context({ "core.memory.backend": "qdrant" });
    expect(stepIds("memory", qdrant)).toEqual(["backend", "connection", "test", "review"]);
    const connection = guideById("memory")!
      .steps(qdrant)
      .find((s) => s.id === "connection");
    expect(connection?.keys).toEqual([
      "core.memory.qdrant.url",
      "core.memory.qdrant.api_key",
      "core.memory.top_k",
    ]);
    expect(guideById("memory")!.steps(qdrant).find((s) => s.id === "test")?.probe).toBe("qdrant");
  });

  it("offers a backend whose keys declare no probe its keys and no test", () => {
    const other = context({ "core.memory.backend": "vectorhub" });
    expect(stepIds("memory", other)).toEqual(["backend", "connection", "review"]);
  });

  it("blocks the test until it has passed", () => {
    const values = { "core.memory.backend": "qdrant" };
    expect(blockedReason("memory", "test", context(values))).toBe("run the test first");
    expect(blockedReason("memory", "test", context(values, { probes: ["qdrant"] }))).toBeNull();
  });
});

describe("the enrichment guide", () => {
  it("offers both feeds and blocks on neither, since either key may stay empty", () => {
    const guide = guideById("enrichment")!;
    const steps = guide.steps(context());
    expect(steps.map((s) => s.id)).toEqual(["switch", "virustotal", "abuseipdb", "review"]);
    expect(steps.map((s) => s.probe)).toEqual([undefined, "virustotal", "abuseipdb", undefined]);
    for (const step of steps) {
      expect(step.canContinue?.(context()) ?? null).toBeNull();
    }
  });
});

describe("the llm guide", () => {
  it("offers the Anthropic base URL among the credentials, folded away as advanced", () => {
    const guide = guideById("llm")!;
    const credentials = guide
      .steps(context({ "core.llm.provider": "anthropic" }))
      .find((s) => s.id === "credentials")!;
    expect(credentials.keys).toEqual([
      "core.llm.anthropic.api_key",
      "core.llm.anthropic.base_url",
      "core.llm.anthropic.allow_plain_http_to_docker_host",
      "core.llm.anthropic.effort",
      "core.llm.anthropic.prompt_cache_ttl",
    ]);
    expect(credentials.advancedKeys).toEqual([
      "core.llm.anthropic.base_url",
      "core.llm.anthropic.allow_plain_http_to_docker_host",
      "core.llm.anthropic.effort",
      "core.llm.anthropic.prompt_cache_ttl",
    ]);
  });
});
