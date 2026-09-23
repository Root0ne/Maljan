import { describe, expect, it } from "vitest";

import type { MalwareReport } from "@/types/malware-report";
import {
  c2Channels,
  channelEvidence,
  executionFlow,
  flowMark,
  hasTechnicalAnalysis,
  keyFindings,
  noSummaryReason,
} from "../reportProse";

function report(over: Partial<MalwareReport>): MalwareReport {
  return over as MalwareReport;
}

describe("the key findings", () => {
  it("are read as the model wrote them, empty text left out", () => {
    const mr = report({
      key_findings: [
        { text: "It persists through a Run key.", evidence_ids: ["ev_0012"] },
        { text: "   ", evidence_ids: [] },
      ],
    });
    expect(keyFindings(mr)).toEqual([
      { text: "It persists through a Run key.", evidence_ids: ["ev_0012"] },
    ]);
  });

  it("are absent on a report stored before them", () => {
    expect(keyFindings(report({}))).toEqual([]);
  });
});

describe("an absent summary says why", () => {
  it("reads the reason the report recorded", () => {
    const mr = report({
      degradation_reasons: ["the report model wrote no summary: the round timed out"],
    });
    expect(noSummaryReason(mr)).toBe("the round timed out");
  });

  it("says nothing on a report that recorded no such reason", () => {
    expect(noSummaryReason(report({ degradation_reasons: ["sandbox unreachable"] }))).toBe("");
  });
});

describe("the execution flow", () => {
  it("is ordered by the model's own order and keeps each mark", () => {
    const mr = report({
      technical_analysis: {
        execution_flow: [
          { order: 2, action: "Creates a mutex", voice: "observed", evidence_refs: ["ev_2"] },
          { order: 1, action: "Resolves APIs", voice: "assessed", evidence_refs: [] },
        ],
      },
    });
    const steps = executionFlow(mr);
    expect(steps.map((s) => s.action)).toEqual(["Resolves APIs", "Creates a mutex"]);
    expect(steps.map(flowMark)).toEqual(["assessed", "observed in sandbox"]);
  });
});

describe("the technical-analysis panel", () => {
  it("draws only when the model wrote one of its blocks", () => {
    expect(hasTechnicalAnalysis(report({}))).toBe(false);
    expect(hasTechnicalAnalysis(report({ technical_analysis: {} }))).toBe(false);
    expect(
      hasTechnicalAnalysis(
        report({
          c2_channels: [
            {
              name: "HTTP gate",
              protocol: "HTTP",
              encryption: null,
              packet_layout: null,
              beacon_format: null,
              evidence_ref: null,
            },
          ],
        }),
      ),
    ).toBe(true);
  });

  it("cites a stored channel's single ref beside the new list, once", () => {
    const [channel] = c2Channels(
      report({
        c2_channels: [
          {
            name: "HTTP gate",
            protocol: "HTTP",
            encryption: null,
            packet_layout: null,
            beacon_format: null,
            evidence_ref: "ev_0009",
            evidence_refs: ["ev_0009", "ev_0010"],
          },
        ],
      }),
    );
    expect(channelEvidence(channel)).toEqual(["ev_0009", "ev_0010"]);
  });
});
