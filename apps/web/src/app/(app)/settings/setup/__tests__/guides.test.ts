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
  "core.sandbox.rest.base_url",
  "core.sandbox.rest.submit.method",
  "core.sandbox.rest.submit.path",
  "core.sandbox.rest.status.path",
  "core.sandbox.rest.report.path",
  "core.sandbox.rest.report.format",
  "core.memory.backend",
];

const schema: SettingsSchema = {
  groups: [{ key: "all", title: "All", description: "", entries: KEYS.map(entry) }],
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
        const copy = providerChoiceCopy(key, choice);
        expect(copy.title).not.toBe(choice);
        expect(copy.blurb.length).toBeGreaterThan(10);
      }
    }
    // An unknown choice still gets a card, under its own id.
    expect(providerChoiceCopy("core.static.provider", "future")).toEqual({
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
  it("asks which server before it shows any field", () => {
    expect(stepIds("tool-server", context())).toEqual([
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
  it("skips the Qdrant steps for the in-process backend", () => {
    expect(stepIds("memory", context({ "core.memory.backend": "memory" }))).toEqual([
      "backend",
      "review",
    ]);
    expect(stepIds("memory", context({ "core.memory.backend": "qdrant" }))).toEqual([
      "backend",
      "qdrant",
      "test",
      "review",
    ]);
  });

  it("blocks the Qdrant test until it has passed", () => {
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
