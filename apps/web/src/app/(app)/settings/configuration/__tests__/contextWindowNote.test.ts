import { describe, expect, it } from "vitest";
import { contextWindowNote } from "../contextWindowNote";
import type { ContextWindow } from "@/types/settings";

/**
 * The tool-output cap defaults to zero, and zero means the served model's
 * context window decides. That window is the one thing an operator cannot see
 * anywhere on the settings page, so it is printed beside the field — with
 * where it was learned, because a `fallback` is the case they have to act on.
 */
function window(over: Partial<ContextWindow> = {}): ContextWindow {
  return {
    tokens: 32768,
    source: "probed",
    detail: "llama.cpp /props reported 32,768 tokens",
    chars_per_token: 3,
    reply_tokens: 8192,
    answer_share: 0.125,
    cap: 9216,
    derived: true,
    setting: 0,
    remedy: "",
    ...over,
  };
}

describe("contextWindowNote", () => {
  it("names the window, where it came from, and what it gives one answer", () => {
    const said = contextWindowNote(window());
    expect(said).toContain("32,768 tokens");
    expect(said).toContain("reported by the server");
    expect(said).toContain("9,216 characters");
    expect(said).toContain("3 characters per token");
    expect(said).toContain("8,192 tokens held back");
  });

  it("names the word the run summary and the API use", () => {
    for (const source of ["declared", "probed", "table"] as const) {
      expect(contextWindowNote(window({ source }))).toContain(`(${source} —`);
    }
  });

  it("says an unknown window is unknown and derives nothing from it", () => {
    const said = contextWindowNote(
      window({
        source: "fallback",
        tokens: 8192,
        cap: 6000,
        remedy: "set core.llm.openai.context_size",
      }),
    );
    expect(said).toContain("unknown");
    expect(said).toContain("fallback");
    expect(said).toContain("6,000 characters");
    expect(said).toContain("set core.llm.openai.context_size");
    expect(said).not.toContain("characters per token");
    expect(said).not.toContain("8,192");
  });

  it("tells a vendored figure from a probed one", () => {
    expect(contextWindowNote(window({ source: "table" }))).toContain("vendored table");
    expect(contextWindowNote(window({ source: "declared" }))).toContain("settings");
  });

  it("says the window decides nothing when the operator set the cap", () => {
    const said = contextWindowNote(window({ derived: false, setting: 6000, cap: 6000 }));
    expect(said).toContain("6,000 characters");
    expect(said).toContain("not what decides it");
  });
});
