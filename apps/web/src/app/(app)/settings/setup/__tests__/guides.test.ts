import { describe, expect, it } from "vitest";
import served from "@/test-fixtures/settings-schema.json";
import type { CatalogEntry, SettingsSchema } from "@/types/settings";
import { GUIDES, guideById, providerChoiceCopy, type GuideContext } from "../guides";

/**
 * The guides are pure functions of a `GuideContext`, so they can be walked
 * without React: this builds a context by hand, per branch, and asserts the
 * step order and the reasons Continue is blocked.
 */

/** The schema the API serves a fresh deployment, as
 *  `scripts/dev/write_console_schema.py` writes it (and a test on the API side
 *  keeps it current): the guides are walked against the real catalogue. */
const SERVED = served as unknown as SettingsSchema;

/** A memory backend a package might register, with keys but no probe: the one
 *  thing the served catalogue cannot show. */
const INVENTED_BACKEND: CatalogEntry = {
  ...(SERVED.groups.flatMap((g) => g.entries).find((e) => e.key === "core.memory.qdrant.url") as CatalogEntry),
  key: "core.memory.vectorhub.endpoint",
  path: "memory.vectorhub.endpoint",
  probe: null,
  applies_when: null,
};

const schema: SettingsSchema = {
  ...SERVED,
  groups: [
    ...SERVED.groups,
    { key: "invented", title: "Invented", description: "", entries: [INVENTED_BACKEND] },
  ],
};

const allKeys = schema.groups.flatMap((g) => g.entries).map((e) => e.key);
const keysUnder = (prefix: string) => allKeys.filter((key) => key.startsWith(prefix));

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

  it("shows CAPE's token, URL, poll and timeout up front and folds its MCP sidecar away", () => {
    const values = { "core.sandbox.provider": "cape2" };
    const fields = guideById("sandbox")!.steps(context(values))[1];
    const folded = fields.advancedKeys ?? [];
    expect(fields.keys!.filter((key) => !folded.includes(key))).toEqual([
      "core.sandbox.cape2.api_token",
      "core.sandbox.cape2.base_url",
      "core.sandbox.cape2.poll_interval_seconds",
      "core.sandbox.cape2.timeout_seconds",
    ]);
    expect(folded).toEqual(keysUnder("core.sandbox.cape2.mcp."));
    expect(folded.length).toBeGreaterThan(0);
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
    expect(connection?.keys).toEqual([...keysUnder("core.memory.qdrant."), "core.memory.top_k"]);
    expect(connection?.keys).toContain("core.memory.qdrant.url");
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
