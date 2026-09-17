import { describe, expect, it } from "vitest";

import type { JobDTO, ReportSummaryDTO } from "@/lib/api";
import {
  analysisRows,
  countByStatus,
  sampleLabel,
  statusFilterFrom,
} from "@/lib/analyses";

function job(over: Partial<JobDTO> = {}): JobDTO {
  return {
    id: "job-1",
    sample_id: "11111111-2222-3333-4444-555555555555",
    sample_filename: "invoice.exe",
    sample_sha256: "a".repeat(64),
    status: "completed",
    config: null,
    created_at: "2026-09-17T09:00:00Z",
    started_at: "2026-09-17T09:00:01Z",
    completed_at: "2026-09-17T09:04:00Z",
    duration_seconds: 239,
    error_message: null,
    ...over,
  };
}

function report(over: Partial<ReportSummaryDTO> = {}): ReportSummaryDTO {
  return {
    id: "report-1",
    job_id: "job-1",
    sample_filename: "invoice.exe",
    verdict: "Malware",
    overall_confidence: 0.91,
    malware_category: "ransomware",
    created_at: "2026-09-17T09:04:00Z",
    techniques_count: 7,
    findings_count: 3,
    ...over,
  };
}

describe("how a run names its sample", () => {
  it("prefers the filename", () => {
    expect(sampleLabel(job())).toBe("invoice.exe");
  });

  it("falls back to a hash prefix, then to the sample id", () => {
    expect(sampleLabel(job({ sample_filename: null }))).toBe(`${"a".repeat(16)}…`);
    expect(sampleLabel(job({ sample_filename: null, sample_sha256: null }))).toBe("11111111-222");
  });
});

describe("one list from the two endpoints", () => {
  it("carries the verdict of the report that belongs to the job", () => {
    const rows = analysisRows([job()], [report()]);
    expect(rows).toHaveLength(1);
    expect(rows[0].verdict).toBe("Malware");
    expect(rows[0].confidence).toBeCloseTo(0.91);
    expect(rows[0].malwareCategory).toBe("ransomware");
    expect(rows[0].status).toBe("completed");
  });

  it("lists a running job, which has no report and is still an analysis", () => {
    const rows = analysisRows(
      [job({ id: "job-2", status: "running", duration_seconds: null })],
      [],
    );
    expect(rows[0].verdict).toBeNull();
    expect(rows[0].status).toBe("running");
  });

  it("does not attach a report to the wrong job", () => {
    const rows = analysisRows([job()], [report({ job_id: "job-9" })]);
    const first = rows.find((r) => r.id === "job-1");
    expect(first?.verdict).toBeNull();
  });

  it("keeps a report whose job this page of jobs did not reach", () => {
    // The two endpoints page independently, so a verdict is not dropped for
    // landing outside the window of jobs that was asked for.
    const rows = analysisRows([job()], [report(), report({ id: "r2", job_id: "job-7" })]);
    expect(rows.map((r) => r.id)).toEqual(["job-1", "job-7"]);
    expect(rows[1].status).toBe("completed");
  });

  it("answers an empty list for nothing at all", () => {
    expect(analysisRows(null, null)).toEqual([]);
  });
});

describe("the status filter, which is where /reports went", () => {
  it("reads a status the list knows", () => {
    expect(statusFilterFrom("completed")).toBe("completed");
    expect(statusFilterFrom("FAILED")).toBe("failed");
  });

  it("falls back to everything for anything else", () => {
    expect(statusFilterFrom("malicious")).toBe("all");
    expect(statusFilterFrom(null)).toBe("all");
  });

  it("counts the rows per status", () => {
    const rows = analysisRows(
      [job(), job({ id: "job-2", status: "failed" }), job({ id: "job-3", status: "failed" })],
      [],
    );
    expect(countByStatus(rows)).toEqual({ completed: 1, failed: 2 });
  });
});
