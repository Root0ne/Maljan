import { describe, expect, it } from "vitest";
import served from "@/test-fixtures/settings-schema.json";
import type { SettingsSchema } from "@/types/settings";
import { guideStatus, llmLooksConfigured } from "../status";

/** The schema the API serves, with each LLM provider's own declaration. */
const SCHEMA = served as unknown as SettingsSchema;

/** A tiny stand-in for the settings context: a flat map of effective values
 *  plus the set of secret keys the server reports as stored. */
function ctx(values: Record<string, unknown>, secrets: string[] = []) {
  const effective = (key: string) => values[key];
  const isSet = (key: string) => secrets.includes(key);
  return { effective, isSet };
}

describe("llmLooksConfigured", () => {
  it("is false with no provider at all", () => {
    const { effective, isSet } = ctx({});
    expect(llmLooksConfigured(effective, isSet)).toBe(false);
  });

  it("is false for ollama without a base URL", () => {
    const { effective, isSet } = ctx({ "core.llm.provider": "ollama", "core.llm.ollama.base_url": "" });
    expect(llmLooksConfigured(effective, isSet)).toBe(false);
  });

  it("is true for ollama with a base URL", () => {
    const { effective, isSet } = ctx({
      "core.llm.provider": "ollama",
      "core.llm.ollama.base_url": "http://127.0.0.1:11434",
    });
    expect(llmLooksConfigured(effective, isSet)).toBe(true);
  });

  it("is false for a hosted provider with no key and true once the key is set", () => {
    const values = { "core.llm.provider": "openai" };
    expect(llmLooksConfigured(ctx(values).effective, ctx(values).isSet)).toBe(false);
    const withKey = ctx(values, ["core.llm.openai.api_key"]);
    expect(llmLooksConfigured(withKey.effective, withKey.isSet, SCHEMA)).toBe(true);
  });

  /* The same credential also has a flat catalog key, and an operator
   * who filled that one in was still told the model was not configured. */
  it("accepts the flat shortcut key for each hosted provider", () => {
    const flat: [string, string][] = [
      ["openai", "core.openai_api_key"],
      ["anthropic", "core.anthropic_api_key"],
      ["gemini", "core.google_api_key"],
    ];
    for (const [provider, key] of flat) {
      const values = { "core.llm.provider": provider };
      const withFlat = ctx(values, [key]);
      expect(llmLooksConfigured(withFlat.effective, withFlat.isSet, SCHEMA)).toBe(true);
    }
  });

  it("does not accept another provider's flat key", () => {
    const withOther = ctx({ "core.llm.provider": "anthropic" }, ["core.openai_api_key"]);
    expect(llmLooksConfigured(withOther.effective, withOther.isSet, SCHEMA)).toBe(false);
  });
});

describe("llmLooksConfigured without a schema yet", () => {
  it("counts a stored key or a set address of the provider's own block", () => {
    const keyed = ctx({ "core.llm.provider": "openai" }, ["core.llm.openai.api_key"]);
    expect(llmLooksConfigured(keyed.effective, keyed.isSet)).toBe(true);
    const local = ctx({ "core.llm.provider": "ollama", "core.llm.ollama.base_url": "http://x" });
    expect(llmLooksConfigured(local.effective, local.isSet)).toBe(true);
    expect(llmLooksConfigured(ctx({ "core.llm.provider": "x" }).effective, () => false)).toBe(false);
  });
});

describe("guideStatus", () => {
  it("names the provider and both models, or says it is not configured", () => {
    const bare = ctx({ "core.llm.provider": "openai" });
    expect(guideStatus("llm", bare.effective, bare.isSet, undefined, SCHEMA)).toBe("Not configured");
    const done = ctx(
      {
        "core.llm.provider": "openai",
        "core.llm.openai.expert_model": "gpt-4o",
        "core.llm.openai.judge_model": "gpt-4o-mini",
      },
      ["core.llm.openai.api_key"]
    );
    expect(guideStatus("llm", done.effective, done.isSet, undefined, SCHEMA)).toBe(
      "OpenAI · expert gpt-4o · judge gpt-4o-mini"
    );
  });

  it("reports the static provider, and none as none", () => {
    const none = ctx({ "core.static.provider": "none" });
    expect(guideStatus("static", none.effective, none.isSet)).toBe("none");
    const ghidra = ctx({ "core.static.provider": "ghidra" });
    expect(guideStatus("static", ghidra.effective, ghidra.isSet)).toBe("ghidra");
  });

  it("spells out what the mock sandbox is", () => {
    const mock = ctx({ "core.sandbox.provider": "mock" });
    expect(guideStatus("sandbox", mock.effective, mock.isSet)).toBe("mock (built-in fixtures)");
    const cape = ctx({ "core.sandbox.provider": "cape2" });
    expect(guideStatus("sandbox", cape.effective, cape.isSet)).toBe("cape2");
  });

  it("counts enabled tool servers", () => {
    const empty = ctx({ "core.mcp.servers": {} });
    expect(guideStatus("tool-server", empty.effective, empty.isSet)).toBe("No servers enabled");
    const two = ctx({
      "core.mcp.servers": {
        a: { enabled: true },
        b: { enabled: true },
        c: { enabled: false },
      },
    });
    expect(guideStatus("tool-server", two.effective, two.isSet)).toBe("2 servers enabled");
  });

  it("counts enabled custom agents and names the active profile", () => {
    const none = ctx({
      "core.agents.definitions": { static: { enabled: true } },
      "core.agents.profile": "default",
    });
    expect(guideStatus("agent", none.effective, none.isSet)).toBe(
      "No custom analysts · active profile default"
    );
    const one = ctx({
      "core.agents.definitions": {
        static: { enabled: true },
        packer: { enabled: true },
        idle: { enabled: false },
      },
      "core.agents.profile": "deep",
    });
    expect(guideStatus("agent", one.effective, one.isSet)).toBe(
      "1 custom analyst enabled · active profile deep"
    );
  });

  it("names the memory backend, and its URL when the backend declares one", () => {
    const mem = ctx({ "core.memory.backend": "memory" });
    expect(guideStatus("memory", mem.effective, mem.isSet)).toBe("memory");
    const qdrant = ctx({
      "core.memory.backend": "qdrant",
      "core.memory.qdrant.url": "http://localhost:6333",
    });
    expect(guideStatus("memory", qdrant.effective, qdrant.isSet)).toBe(
      "qdrant · http://localhost:6333"
    );
    const noUrl = ctx({ "core.memory.backend": "qdrant", "core.memory.qdrant.url": "" });
    expect(guideStatus("memory", noUrl.effective, noUrl.isSet)).toBe("qdrant · no URL set");
    const other = ctx({
      "core.memory.backend": "vectorhub",
      "core.memory.vectorhub.url": "http://store:9000",
    });
    expect(guideStatus("memory", other.effective, other.isSet)).toBe(
      "vectorhub · http://store:9000"
    );
  });

  it("shows the label each backend declares beside its id", () => {
    /* As the catalogue serves it: `choice_labels` on core.memory.backend. */
    const labels: Record<string, string> = { memory: "in-process", vectorhub: "hosted" };
    const label = (key: string, choice: string) =>
      key === "core.memory.backend" ? labels[choice] : undefined;
    const mem = ctx({ "core.memory.backend": "memory" });
    expect(guideStatus("memory", mem.effective, mem.isSet, label)).toBe("memory (in-process)");
    const qdrant = ctx({
      "core.memory.backend": "qdrant",
      "core.memory.qdrant.url": "http://localhost:6333",
    });
    expect(guideStatus("memory", qdrant.effective, qdrant.isSet, label)).toBe(
      "qdrant · http://localhost:6333"
    );
    const other = ctx({
      "core.memory.backend": "vectorhub",
      "core.memory.vectorhub.url": "http://store:9000",
    });
    expect(guideStatus("memory", other.effective, other.isSet, label)).toBe(
      "vectorhub (hosted) · http://store:9000"
    );
  });

  it("reports enrichment on or off and which keys are set", () => {
    const off = ctx({ "api.enrichment_enabled": false });
    expect(guideStatus("enrichment", off.effective, off.isSet)).toBe("Off");
    const onNoKeys = ctx({ "api.enrichment_enabled": true });
    expect(guideStatus("enrichment", onNoKeys.effective, onNoKeys.isSet)).toBe("On · no keys set");
    const onKeys = ctx({ "api.enrichment_enabled": true }, [
      "api.virustotal_api_key",
      "api.abuseipdb_api_key",
    ]);
    expect(
      guideStatus("enrichment", onKeys.effective, onKeys.isSet, undefined, SCHEMA)
    ).toBe("On · VirusTotal, AbuseIPDB");
  });

  it("names a source declared only as data once its own key is stored", () => {
    const schema: SettingsSchema = {
      ...SCHEMA,
      enrichment_sources: [
        ...(SCHEMA.enrichment_sources ?? []),
        {
          key: "domainrep",
          label: "Domain reputation",
          kinds: ["domain"],
          enabled: true,
          credential_key: null,
          own_credential: true,
          server: null,
          probe: true,
        },
      ],
    };
    const stored = ctx(
      {
        "api.enrichment_enabled": true,
        "api.enrichment_sources": { domainrep: { api_key: "**********" } },
      },
      ["api.virustotal_api_key"]
    );
    expect(guideStatus("enrichment", stored.effective, stored.isSet, undefined, schema)).toBe(
      "On · VirusTotal, Domain reputation"
    );
  });
});
