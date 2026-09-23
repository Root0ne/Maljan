import { describe, expect, it } from "vitest";

import { buildConversation, fallbackLine, restedLine } from "@/lib/conversation";
import type { RunEvent } from "@/lib/runStore";
import { serverRestSentence, tokensSentence } from "@/lib/report-utils";
import { moveChoice, storedChoice } from "@/app/(app)/settings/configuration/modelList";

/**
 * What the console says about a run's models and tool servers: which model
 * answered a turn a fallback gave, which server was rested, and what the run
 * spent — in the words the report prints.
 */

let seq = 0;
function event(type: string, data: Record<string, unknown> = {}): RunEvent {
  seq += 1;
  return { type, data, ts: "2026-09-17T10:00:00Z", seq, order: seq, sortKey: seq };
}

function texts(events: RunEvent[]): string[] {
  const { stages } = buildConversation(events, null);
  return stages.flatMap((stage) =>
    stage.rounds.flatMap((round) => round.items.map((item) => `${item.kind}: ${item.text}`)),
  );
}

describe("a turn a fallback model gave", () => {
  it("is named where it happened, with the model and the reason", () => {
    const lines = texts([
      event("agent_message_delta", { stage: "a", agent: "static", text_delta: "Reading the imports" }),
      event("model_fallback", {
        stage: "a",
        agent: "static",
        model: "ollama/gemma",
        reason: "openai/qwen: the provider timed out; answered by ollama/gemma, which answers the rest of this loop",
      }),
    ]);
    expect(lines).toEqual([
      "says: Reading the imports",
      "system: Static's turn was answered by ollama/gemma — openai/qwen: the provider timed out; answered by ollama/gemma, which answers the rest of this loop.",
    ]);
  });

  it("is named when no text was streamed at all", () => {
    const lines = texts([
      event("model_fallback", {
        stage: "a",
        agent: "static",
        model: "ollama/gemma",
        reason: "openai/qwen: the provider could not be reached",
      }),
    ]);
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^system: Static's turn was answered by ollama\/gemma/);
  });

  it("leaves a turn that only carries its tokens out of the conversation", () => {
    const lines = texts([
      event("agent_message_delta", {
        stage: "a",
        agent: "static",
        text_delta: "",
        model: "openai/qwen",
        tokens: { input_tokens: 10, output_tokens: 2 },
      }),
    ]);
    expect(lines).toEqual([]);
  });

  it("says who fell back when the model is not named", () => {
    expect(fallbackLine("Static", "", "x: timed out")).toBe("Static fell back — x: timed out.");
  });
});

describe("a rested tool server", () => {
  it("is a line in the conversation", () => {
    const lines = texts([
      event("tool_server_rested", {
        server: "analysis",
        failures: 3,
        cooldown_s: 60,
        reason: "the server did not answer in time",
      }),
    ]);
    expect(lines).toEqual([
      "system: Tool server analysis is resting for 60 s after 3 calls in a row it did not answer (the last: the server did not answer in time).",
    ]);
  });

  it("counts one failure in the singular", () => {
    expect(restedLine({ server: "s", failures: 1, cooldown_s: 5 })).toContain("1 call in a row it did not answer");
  });

  it("is recorded in the words the report prints", () => {
    expect(serverRestSentence({ server: "analysis", failures: 3, cooldown_s: 60, reason: "timed out" })).toBe(
      "Tool server analysis was rested for 60 s after 3 calls in a row it did not answer (the last: timed out).",
    );
  });
});

describe("what the run spent", () => {
  it("prints the report's own sentence when the summary carries it", () => {
    expect(tokensSentence({ llm_calls: 2, sentence: "Tokens: 1 in and 2 out over 2 model calls." })).toBe(
      "Tokens: 1 in and 2 out over 2 model calls.",
    );
  });

  it("says a count the provider did not report is not reported", () => {
    expect(tokensSentence({ llm_calls: 3, unreported_calls: 3 })).toBe(
      "Tokens: not reported by the provider for any of 3 model calls.",
    );
    expect(
      tokensSentence({ llm_calls: 3, unreported_calls: 1, input_tokens: 1200, output_tokens: 80 }),
    ).toBe("Tokens: 1,200 in and 80 out over 3 model calls; not reported for 1 of them.");
  });

  it("never prints a figure an older run estimated as a count", () => {
    const text = tokensSentence({ llm_calls: 4, input_tokens: 999, output_tokens: 9, estimated_calls: 2 });
    expect(text).not.toContain("999");
    expect(text).toContain("estimates");
  });

  it("names a cost only where the provider reported one", () => {
    expect(
      tokensSentence({ llm_calls: 1, input_tokens: 1, output_tokens: 1, cost: 0.5, cost_calls: 1 }),
    ).toContain("a cost of 0.5000 USD as the provider reported it for 1 call");
    expect(tokensSentence({ llm_calls: 1, input_tokens: 1, output_tokens: 1 })).not.toContain("cost");
  });

  it("is absent on a run that made no model call", () => {
    expect(tokensSentence({ llm_calls: 0 })).toBeNull();
    expect(tokensSentence(null)).toBeNull();
  });
});

describe("the fallback list in the agent editor", () => {
  const rows = [
    { provider: "ollama", model: "a" },
    { provider: "ollama", model: "b" },
    { provider: "anthropic", model: "c" },
  ];

  it("moves a row up and down, and not past either end", () => {
    expect(moveChoice(rows, 2, -1).map((r) => r.model)).toEqual(["a", "c", "b"]);
    expect(moveChoice(rows, 0, 1).map((r) => r.model)).toEqual(["b", "a", "c"]);
    expect(moveChoice(rows, 0, -1)).toBe(rows);
    expect(moveChoice(rows, 2, 1)).toBe(rows);
  });

  it("stages a row once it names a provider and a model, with an endpoint only where one is taken", () => {
    expect(storedChoice({ provider: "ollama", model: "" })).toBeNull();
    expect(storedChoice({ provider: "anthropic", model: "c", base_url: "http://x" })).toEqual({
      provider: "anthropic",
      model: "c",
    });
    expect(storedChoice({ provider: "ollama", model: "g", base_url: "http://box:11434" })).toEqual({
      provider: "ollama",
      model: "g",
      base_url: "http://box:11434",
    });
  });
});
