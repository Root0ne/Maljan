import { describe, expect, it } from "vitest";

import type { EvidenceEntry } from "@/types/evidence";
import { entryNotes } from "../evidenceRows";

function entry(over: Partial<EvidenceEntry> = {}): EvidenceEntry {
  return {
    id: "1",
    entry_id: "ev_0001",
    stage: "analysis",
    agent: "static",
    server: null,
    tool: "strings",
    ok: true,
    duration_ms: 10,
    seq: 1,
    args: null,
    output: "text",
    structured: null,
    created_at: null,
    ...over,
  };
}

describe("what a row says about how its answer was kept", () => {
  it("says nothing for an entry that carries none of the facts", () => {
    expect(entryNotes(entry())).toEqual([]);
  });

  it("says how much the guardrail cut from the answer the model read", () => {
    expect(entryNotes(entry({ truncated: true, chars_dropped: 12345 }))).toEqual([
      "The tool-output guardrail cut 12,345 characters from the answer the model read.",
    ]);
  });

  it("says a kept output was shortened when the cut was not counted", () => {
    expect(entryNotes(entry({ truncated: true }))).toEqual([
      "The answer the model read was shortened to keep this agent inside its byte budget.",
    ]);
    // An empty output's trim is already said where the output would be.
    expect(entryNotes(entry({ truncated: true, output: "" }))).toEqual([]);
  });

  it("names the parts kept whole elsewhere, and a part that could not be", () => {
    expect(
      entryNotes(
        entry({
          spilled: [
            { part: "structured_content", key: "k1", bytes: 2048 },
            { part: "output", error: "upload refused" },
          ],
        }),
      ),
    ).toEqual([
      "The full structured content (2,048 bytes) is kept whole in object storage.",
      "The full output could not be kept: upload refused",
    ]);
  });

  it("says a call answered from an earlier one and arguments that were repaired", () => {
    expect(entryNotes(entry({ repeated_of: "ev_0003", args_repaired: true }))).toEqual([
      "Answered from the earlier identical call ev_0003, not run again.",
      "The model's arguments arrived cut off and were closed before the call ran.",
    ]);
  });
});
