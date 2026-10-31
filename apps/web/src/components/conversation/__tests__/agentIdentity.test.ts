import { describe, expect, it } from "vitest";

import { MODERATOR_TONE, agentInitials, agentTones, toneOf } from "../agentIdentity";
import { writingLine } from "../ConversationPanel";

/**
 * Telling agents apart: a colour per agent that holds from run to run, never
 * shared within a run while the palette lasts, and the moderators drawn in a
 * tone of their own.
 */

describe("agent tones", () => {
  it("gives the agents of one run different colours while the palette lasts", () => {
    const tones = agentTones(["static", "dynamic", "network", "triage", "reverser"]);
    const colours = Object.values(tones).map((t) => t.color);
    expect(new Set(colours).size).toBe(5);
  });

  it("keeps an agent's colour whatever order the cast is listed in", () => {
    const one = agentTones(["static", "dynamic"]);
    const two = agentTones(["dynamic", "static"]);
    expect(one.static.color).toBe(two.static.color);
  });

  it("draws the moderators in the moderator's tone, and no agent in it", () => {
    const tones = agentTones(["judge", "a", "b", "c", "d", "e", "f"], new Set(["judge"]));
    expect(tones.judge).toBe(MODERATOR_TONE);
    expect(Object.entries(tones).filter(([key, t]) => key !== "judge" && t.moderator)).toEqual([]);
  });

  it("derives the wash and the ink from the one token", () => {
    const tone = agentTones(["static"]).static;
    expect(tone.wash).toBe(`color-mix(in srgb, ${tone.color} 15%, transparent)`);
    expect(tone.ink).toBe(`color-mix(in srgb, ${tone.color} 70%, var(--text-primary))`);
    expect(toneOf({}, "nobody").color).toBe("var(--text-muted)");
  });
});

describe("agent initials", () => {
  it("never draws a separator as an initial", () => {
    const initials = agentInitials({
      static: "Static analyst",
      static_disasm: "Static analyst (disassembler)",
      static_scan: "Static analyst (scanner)",
    });
    expect(new Set(Object.values(initials)).size).toBe(3);
    for (const value of Object.values(initials)) expect(value).toMatch(/^[A-Z][a-z0-9]$/i);
  });
});

describe("the writing line", () => {
  it("names who is writing", () => {
    expect(writingLine([])).toBe("");
    expect(writingLine(["Static analyst"])).toBe("Static analyst is writing…");
    expect(writingLine(["A", "B"])).toBe("A and B are writing…");
    expect(writingLine(["A", "B", "C", "D"])).toBe("A, B and 2 others are writing…");
  });
});
