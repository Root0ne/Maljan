import { describe, expect, it } from "vitest";

import type { ProbeResult } from "@/types/settings";
import {
  capabilityCells,
  enabledCount,
  matchingTools,
  setTools,
  toolRows,
} from "../toolTableRows";

const MANIFEST = ["open_file", "analyze", "list_imports", "decompile"];

function probe(details: ProbeResult["details"]): ProbeResult {
  return { ok: true, latency_ms: 5, detail: "", models: null, tools: MANIFEST, details };
}

const WITH_MANIFEST = probe({
  capabilities: {
    server: "r2custom",
    version: "1",
    tools: [
      { name: "open_file", optional_dependency: null, available: true, reason: null, timeout_s: null },
      {
        name: "decompile",
        optional_dependency: "decompiler-plugin",
        available: false,
        reason: "the decompiler plugin is not installed",
        timeout_s: null,
        remediation: "install the plugin on the sidecar host",
        without: "disassembly",
      },
    ],
  },
});

describe("the per-tool table", () => {
  it("counts every tool as enabled when the list is the built-in's null", () => {
    expect(enabledCount(MANIFEST, null)).toBe(4);
    expect(enabledCount(MANIFEST, ["analyze", "gone_tool"])).toBe(1);
    expect(enabledCount(MANIFEST, [])).toBe(0);
  });

  it("narrows by a case-insensitive part of the name, in the manifest's order", () => {
    expect(matchingTools(MANIFEST, "")).toEqual(MANIFEST);
    expect(matchingTools(MANIFEST, "  I")).toEqual(["open_file", "list_imports", "decompile"]);
    expect(matchingTools(MANIFEST, "IMPORT")).toEqual(["list_imports"]);
    expect(matchingTools(MANIFEST, "nothing")).toEqual([]);
  });

  it("gives each unavailable tool the manifest's reason, remedy and fallback", () => {
    const rows = toolRows(MANIFEST, ["open_file"], capabilityCells(WITH_MANIFEST), "");
    const decompile = rows.find((r) => r.name === "decompile");
    expect(decompile).toEqual({
      name: "decompile",
      enabled: false,
      available: false,
      reason: "the decompiler plugin is not installed; still answers disassembly; install the plugin on the sidecar host",
    });
    expect(rows.find((r) => r.name === "open_file")).toMatchObject({ enabled: true, available: true, reason: "" });
    // A tool the manifest does not mention is not assumed unavailable.
    expect(rows.find((r) => r.name === "analyze")?.available).toBe(true);
  });

  it("reads a server that offers no capability manifest as saying nothing", () => {
    expect(capabilityCells(probe(null)).size).toBe(0);
    expect(capabilityCells(probe({ capabilities: { tools: "not a list" } } as never)).size).toBe(0);
    expect(toolRows(MANIFEST, null, capabilityCells(null), "").every((r) => r.available)).toBe(true);
  });

  it("selects all into an explicit list in the manifest's order", () => {
    expect(setTools(MANIFEST, [], MANIFEST, true)).toEqual(MANIFEST);
    expect(setTools(MANIFEST, null, MANIFEST, true)).toEqual(MANIFEST);
  });

  it("selects none, and turns a built-in's null into an explicit empty list", () => {
    expect(setTools(MANIFEST, null, MANIFEST, false)).toEqual([]);
  });

  it("changes only the tools a search left on screen", () => {
    const shown = matchingTools(MANIFEST, "i");
    expect(setTools(MANIFEST, ["analyze"], shown, true)).toEqual(MANIFEST);
    expect(setTools(MANIFEST, null, shown, false)).toEqual(["analyze"]);
  });

  it("keeps a listed name the manifest no longer offers", () => {
    expect(setTools(MANIFEST, ["retired_tool", "analyze"], ["open_file"], true)).toEqual([
      "open_file",
      "analyze",
      "retired_tool",
    ]);
    expect(setTools(MANIFEST, ["retired_tool", "analyze"], MANIFEST, false)).toEqual(["retired_tool"]);
  });

  it("toggles one tool the way a single tick box did", () => {
    expect(setTools(["open_file", "analyze", "list_imports"], [], ["open_file"], true)).toEqual(["open_file"]);
    expect(
      setTools(["open_file", "analyze", "list_imports"], ["open_file"], ["analyze"], true),
    ).toEqual(["open_file", "analyze"]);
  });
});
