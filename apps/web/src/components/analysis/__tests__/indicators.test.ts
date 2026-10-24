import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { MalwareReport } from "@/types/malware-report";
import IndicatorsPanel from "../IndicatorsPanel";
import {
  decisionOf,
  hasIndicators,
  indicatorRows,
  judgeIndicatorRows,
  mispAbsence,
} from "../indicators";
import { CONSOLIDATED_IOCS, JUDGE_INDICATORS } from "./storedRunShapes";

/** Only the fields the indicator readers look at; the rest of a report is not theirs. */
function report(over: Partial<MalwareReport> = {}): MalwareReport {
  return {
    consolidated_iocs: CONSOLIDATED_IOCS,
    judge_indicators: JUDGE_INDICATORS,
    misp_attributes: null,
    ...over,
  } as MalwareReport;
}

describe("a publish answer read as the export reads it (T-346)", () => {
  it("publishes a yes, with or without its reason", () => {
    expect(decisionOf("yes")).toEqual({ publication: "published", reason: "", answered: true });
    expect(decisionOf("yes: the sample's own digest")).toEqual({
      publication: "published",
      reason: "the sample's own digest",
      answered: true,
    });
  });

  it("withholds a no and keeps its reason", () => {
    const decision = decisionOf("no: it is a public DNS resolver");
    expect(decision.publication).toBe("withheld");
    expect(decision.reason).toBe("it is a public DNS resolver");
  });

  it("withholds a row the rule gave no answer, and invents no reason", () => {
    expect(decisionOf(null)).toEqual({ publication: "withheld", reason: "", answered: false });
  });

  it("keeps an answer it cannot read whole, as a reason", () => {
    expect(decisionOf("yesterday")).toEqual({
      publication: "withheld",
      reason: "yesterday",
      answered: true,
    });
  });
});

describe("the consolidated indicator table (T-346)", () => {
  const rows = indicatorRows(report());

  it("holds every row, typed, in the report's order", () => {
    expect(rows.map((r) => r.type)).toEqual(["SHA-256", "Command line", "Mutex", "IPv4", "URL"]);
    expect(rows.map((r) => r.publication)).toEqual([
      "published",
      "withheld",
      "published",
      "withheld",
      "published",
    ]);
  });

  it("draws each indicator with its type, its decision and the reason", () => {
    const html = renderToStaticMarkup(createElement(IndicatorsPanel, { mr: report() }));
    expect(html).toContain("Indicators (5)");
    expect(html).toContain("3 published · 2 withheld");
    for (const row of CONSOLIDATED_IOCS) {
      expect(html).toContain(row.value);
      expect(html).toContain(row.type);
    }
    expect(html).toContain("the sample&#x27;s own digest");
    expect(html).toContain("the sandbox report does not say which process made the flows to it");
    expect(html).toContain("the publish rule recorded no answer");
    // A reason or a recovery that cites an entry links it.
    expect(html).toContain('evidence?evidence=ev_0018"');
  });

  it("draws the judge's indicators beside the table's decision for each", () => {
    const judged = judgeIndicatorRows(
      report({
        judge_indicators: [
          ...JUDGE_INDICATORS,
          { kind: "domain", value: "absent.invalid", algorithm: "" },
        ],
      }),
    );
    expect(judged.map((j) => j.decision?.publication ?? null)).toEqual([
      "published",
      "published",
      "published",
      null,
    ]);
    expect(judged[1].algorithm).toBe("SHA-256");

    const html = renderToStaticMarkup(
      createElement(IndicatorsPanel, {
        mr: report({
          judge_indicators: [{ kind: "domain", value: "absent.invalid", algorithm: "" }],
        }),
      }),
    );
    expect(html).toContain("Judge&#x27;s indicators (1)");
    expect(html).toContain("not in the indicator table");
  });

  it("offers no panel for lists of malformed rows alone", () => {
    const malformed = report({
      consolidated_iocs: [null, { type: "URL" }] as unknown as MalwareReport["consolidated_iocs"],
      judge_indicators: [{ kind: "url" }] as unknown as MalwareReport["judge_indicators"],
    });
    expect(hasIndicators(malformed)).toBe(false);
  });

  it("draws nothing for a report stored before either field", () => {
    const old = report({ consolidated_iocs: undefined, judge_indicators: undefined });
    expect(hasIndicators(old)).toBe(false);
    expect(renderToStaticMarkup(createElement(IndicatorsPanel, { mr: old }))).toBe("");
  });
});

describe("why the MISP export is empty (T-333)", () => {
  it("does not blame the run when no builder wrote the field", () => {
    const said = mispAbsence(report());
    expect(said).not.toContain("this run generated no MISP attributes");
    expect(said).toContain("the platform does not build them");
    expect(said).toContain("its 5 indicators are on DETECTION");
  });

  it("says a run produced none only when an empty list was written", () => {
    expect(mispAbsence(report({ misp_attributes: [] }))).toBe(
      "this run generated no MISP attributes",
    );
  });
});
