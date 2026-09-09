import { describe, expect, it } from "vitest";
import { guideStatus, llmLooksConfigured } from "../status";

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
    expect(llmLooksConfigured(withKey.effective, withKey.isSet)).toBe(true);
  });

  /* Task 21: the same credential also has a flat catalog key, and an operator
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
      expect(llmLooksConfigured(withFlat.effective, withFlat.isSet)).toBe(true);
    }
  });

  it("does not accept another provider's flat key", () => {
    const withOther = ctx({ "core.llm.provider": "anthropic" }, ["core.openai_api_key"]);
    expect(llmLooksConfigured(withOther.effective, withOther.isSet)).toBe(false);
  });
});

describe("guideStatus", () => {
  it("names the provider and both models, or says it is not configured", () => {
    const bare = ctx({ "core.llm.provider": "openai" });
    expect(guideStatus("llm", bare.effective, bare.isSet)).toBe("Not configured");
    const done = ctx(
      {
        "core.llm.provider": "openai",
        "core.llm.openai.expert_model": "gpt-4o",
        "core.llm.openai.judge_model": "gpt-4o-mini",
      },
      ["core.llm.openai.api_key"]
    );
    expect(guideStatus("llm", done.effective, done.isSet)).toBe(
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

  it("names the memory backend and the Qdrant URL when there is one", () => {
    const mem = ctx({ "core.memory.backend": "memory" });
    expect(guideStatus("memory", mem.effective, mem.isSet)).toBe("memory (in-process)");
    const qdrant = ctx({
      "core.memory.backend": "qdrant",
      "core.memory.qdrant_url": "http://localhost:6333",
    });
    expect(guideStatus("memory", qdrant.effective, qdrant.isSet)).toBe(
      "qdrant · http://localhost:6333"
    );
    const noUrl = ctx({ "core.memory.backend": "qdrant", "core.memory.qdrant_url": "" });
    expect(guideStatus("memory", noUrl.effective, noUrl.isSet)).toBe("qdrant · no URL set");
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
    expect(guideStatus("enrichment", onKeys.effective, onKeys.isSet)).toBe(
      "On · VirusTotal, AbuseIPDB"
    );
  });
});
