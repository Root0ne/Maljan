import { describe, expect, it } from "vitest";

import type { MalwareReport } from "@/types/malware-report";
import {
  c2Channels,
  channelEvidence,
  configFindings,
  defangEndpoint,
  executionFlow,
  flowMark,
  flowNote,
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

describe("a model's endpoint on a reading surface", () => {
  it("is defanged in the forms the exported report uses", () => {
    expect(defangEndpoint("http://c2.example.invalid/gate")).toBe(
      "hxxp://c2[.]example[.]invalid/gate",
    );
    expect(defangEndpoint("10.0.0.5")).toBe("10[.]0[.]0[.]5");
    expect(defangEndpoint("upload.example.invalid")).toBe("upload[.]example[.]invalid");
    expect(defangEndpoint("hxxp://c2[.]example[.]invalid")).toBe("hxxp://c2[.]example[.]invalid");
  });
});

describe("the platform's note beside a model's row", () => {
  it("names the step a kept finding names", () => {
    const mr = report({
      dynamic: {} as MalwareReport["dynamic"],
      run_summary: {
        validation: {
          unresolved: [
            { agent: "composer", code: "report.flow_voice", message: "step 2 is marked observed" },
          ],
        },
      } as MalwareReport["run_summary"],
    });
    expect(flowNote(mr, { order: 2, action: "x", voice: "observed", evidence_refs: [] })).toBe(
      "unresolved: report.flow_voice",
    );
    expect(flowNote(mr, { order: 1, action: "x", voice: "observed", evidence_refs: [] })).toBe("");
  });

  it("says a step marked observed has no observation to rest on", () => {
    const mr = report({ dynamic: null, network: null });
    expect(flowNote(mr, { order: 1, action: "x", voice: "observed", evidence_refs: [] })).toBe(
      "unresolved: report.flow_voice; no sandbox observation in this run",
    );
  });

  it("names the configuration item a kept finding names", () => {
    const mr = report({
      run_summary: {
        validation: {
          unresolved: [
            {
              agent: "composer",
              code: "report.configuration_uncited",
              message: "configuration item 3 is marked decrypted and cites nothing",
            },
          ],
        },
      } as MalwareReport["run_summary"],
    });
    expect([...configFindings(mr)]).toEqual([3]);
  });
});
