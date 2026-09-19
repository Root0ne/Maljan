import { describe, expect, it } from "vitest";
import { CAP_LABEL, capsHit } from "../pipelineSteps";
import { unavailableTools, type ProbeResult } from "@/types/settings";

describe("the caps a step shows", () => {
  it("reads the distinct caps of an agent from run_summary.budget", () => {
    const summary = { budget: { static: { caps: ["steps", "repeats"] }, network: { caps: [] } } };
    expect(capsHit(summary, "static")).toEqual(["steps", "repeats"]);
    expect(capsHit(summary, "network")).toEqual([]);
    expect(capsHit(summary, "judge")).toEqual([]);
  });

  it("shows nothing for a run stored before the meter", () => {
    expect(capsHit({ stages: [] }, "static")).toEqual([]);
    expect(capsHit(null, "static")).toEqual([]);
  });

  it("has a sentence for every cap the pipeline names", () => {
    for (const cap of ["steps", "time", "repeats", "budget_seconds"]) {
      expect(CAP_LABEL[cap]).toBeTruthy();
    }
  });
});

describe("the unavailable tools of a probe", () => {
  const probe = (details: ProbeResult["details"]): ProbeResult => ({
    ok: true,
    latency_ms: 1,
    detail: "d",
    models: null,
    tools: ["hashes", "document_info"],
    details,
  });

  it("lists the tools the manifest marks unavailable", () => {
    const result = probe({
      capabilities: {
        server: "analysis",
        version: "1",
        tools: [
          { name: "hashes", optional_dependency: null, available: true, reason: null, timeout_s: null },
          {
            name: "document_info",
            optional_dependency: "olefile",
            available: false,
            reason: "olefile is not installed",
            timeout_s: null,
          },
        ],
      },
    });
    expect(unavailableTools(result).map((c) => c.name)).toEqual(["document_info"]);
  });

  it("is empty for a server without a manifest", () => {
    expect(unavailableTools(probe(null))).toEqual([]);
    expect(unavailableTools(probe({ prompt_sha256: "x" }))).toEqual([]);
    expect(unavailableTools(undefined)).toEqual([]);
  });
});
