import { describe, expect, it } from "vitest";

import type { JobDTO, ReportDetailDTO } from "@/lib/api";
import { reportAbsence } from "../reportAbsence";
import { ApiError } from "@/lib/errors";
import { reportFetchError } from "@/components/analysis/polling";

const job = (status: string) => ({ id: "j1", status }) as unknown as JobDTO;
const report = { id: "r1" } as unknown as ReportDetailDTO;

describe("a tab with no report behind it", () => {
  it("draws the report's own answers once there is one", () => {
    expect(reportAbsence({ report, job: job("completed") })).toBeNull();
  });

  it("says a running analysis is still running rather than empty", () => {
    expect(reportAbsence({ report: null, job: job("running") })?.kind).toBe("running");
  });

  it("says nothing is loaded yet while the API has never answered", () => {
    expect(reportAbsence({ report: null, job: null })).toEqual({
      kind: "unanswered",
      text: "Not loaded yet: the API has not answered.",
    });
  });

  it("says a report that could not be read is unknown, not empty", () => {
    const absent = reportAbsence({ report: null, job: job("completed"), reportError: "502" });
    expect(absent?.kind).toBe("unreadable");
    expect(absent?.text).toContain("502");
    expect(absent?.text).toContain("unknown, not empty");
  });

  it("says a finished run whose report read answered 404 ended without one", () => {
    const reportError = reportFetchError(new ApiError("Report not found", 404), true);
    expect(reportAbsence({ report: null, job: job("completed"), reportError })?.text).toBe(
      "This run ended without writing a report, so nothing here was established either way.",
    );
  });

  it("says a finished run that wrote no report established nothing either way", () => {
    for (const status of ["completed", "failed", "cancelled"]) {
      const absent = reportAbsence({ report: null, job: job(status) });
      expect(absent?.kind).toBe("none");
      expect(absent?.text).not.toMatch(/predates/);
    }
  });
});
