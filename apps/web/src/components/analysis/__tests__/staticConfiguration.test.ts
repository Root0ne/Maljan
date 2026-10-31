/**
 * The recovered configuration, drawn once on Static & code (T-465): each
 * item's citation state reads in plain words, as the technical analysis's
 * table printed it before the table moved here.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useParams: () => ({ id: "J1" }) }));

import type { ReportDetailDTO } from "@/lib/api";
import type { MalwareReport } from "@/types/malware-report";
import { REPORT, MALWARE_REPORT } from "../../../../e2e/report-fixture";
import StaticContent from "../tabs/StaticContent";

function draw(over: Partial<MalwareReport>): string {
  const report = { ...REPORT, malware_report: { ...MALWARE_REPORT, ...over } } as ReportDetailDTO;
  return renderToStaticMarkup(createElement(StaticContent, { report }));
}

describe("the configuration's citation state, in plain words", () => {
  const html = draw({
    technical_analysis: {
      configuration: [
        { key: "C2 host", value: "c2.test", how_obtained: "decrypted", evidence_refs: [] },
        { key: "Mutex", value: "Global\\M1", how_obtained: "observed", evidence_refs: ["ev_0004"] },
      ],
    },
    run_summary: {
      ...MALWARE_REPORT.run_summary,
      validation: {
        retries: 0,
        by_code: {},
        unresolved: [
          { agent: "composer", code: "report.configuration_uncited", message: "configuration item 1 is marked decrypted and cites nothing" },
        ],
      },
    } as MalwareReport["run_summary"],
  } as Partial<MalwareReport>);

  it("says an item cites nothing, and what the report's check found, without the check's code", () => {
    expect(html).toContain("no evidence cited");
    expect(html).toContain("(the report&#x27;s check found no evidence for this item)");
    expect(html).not.toContain("report.configuration_uncited");
    // Exactly the item the check named.
    expect(html.match(/the report&#x27;s check found no evidence/g)).toHaveLength(1);
  });

  it("cites a cited item's records instead, and gives every value a copy", () => {
    expect(html.match(/no evidence cited/g)).toHaveLength(1);
    expect(html).toContain("evidence?evidence=ev_0004");
    expect(html).toContain("Copy configuration value C2 host");
    expect(html).toContain("Copy configuration value Mutex");
  });
});
