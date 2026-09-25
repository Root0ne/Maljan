import { describe, expect, it } from "vitest";

import type { JobDTO, ReportSummaryDTO } from "@/lib/api";
import {
  analysisRows,
  countByStatus,
  latestRunRows,
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
    const rows = analysisRows(
      [job()],
      [report(), report({ id: "r2", job_id: "job-7", created_at: "2026-09-16T09:00:00Z" })],
    );
    expect(rows.map((r) => r.id)).toEqual(["job-1", "job-7"]);
    expect(rows[1].status).toBe("completed");
    expect(rows[1].incompleteReason).toBeNull();
  });

  it("marks a report a failed job kept, joined or on its own", () => {
    const note = "This report was built and the run failed after it: node judge raised X.";
    const joined = analysisRows(
      [job({ status: "failed" })],
      [report({ incomplete_reason: note })],
    );
    expect(joined[0].status).toBe("failed");
    expect(joined[0].incompleteReason).toBe(note);

    const alone = analysisRows([], [report({ incomplete_reason: note })]);
    expect(alone[0].status).toBe("failed");
    expect(alone[0].incompleteReason).toBe(note);
  });

  it("orders the whole list newest first, however the rows were built", () => {
    /* The reports appended above have no place in the jobs order, so a run
     * that finished today could otherwise sit under one from last week. */
    const rows = analysisRows(
      [
        job({ id: "job-old", created_at: "2026-09-10T09:00:00Z" }),
        job({ id: "job-new", created_at: "2026-09-17T09:00:00Z" }),
      ],
      [report({ id: "r3", job_id: "job-middle", created_at: "2026-09-14T09:00:00Z" })],
    );
    expect(rows.map((r) => r.id)).toEqual(["job-new", "job-middle", "job-old"]);
  });

  it("answers an empty list for nothing at all", () => {
    expect(analysisRows(null, null)).toEqual([]);
  });

  it("carries the full sha256 from the job, and none for a report-only row", () => {
    const rows = analysisRows([job()], [report({ id: "r2", job_id: "job-7" })]);
    expect(rows.find((r) => r.id === "job-1")?.sha256).toBe("a".repeat(64));
    expect(rows.find((r) => r.id === "job-7")?.sha256).toBeNull();
  });
});

describe("the dashboard's latest runs", () => {
  it("are exactly the jobs asked for, each with its own verdict", () => {
    const rows = latestRunRows(
      [job(), job({ id: "job-2", status: "running", created_at: "2026-09-17T10:00:00Z" })],
      [report(), report({ id: "r9", job_id: "job-9" })],
    );
    expect(rows.map((r) => r.id)).toEqual(["job-2", "job-1"]);
    expect(rows.find((r) => r.id === "job-1")?.verdict).toBe("Malware");
    // Not finished, so no verdict: the row is drawn by its status instead.
    expect(rows.find((r) => r.id === "job-2")?.verdict).toBeNull();
  });

  it("leave a completed job whose report was not fetched without a verdict", () => {
    const rows = latestRunRows([job()], []);
    expect(rows).toHaveLength(1);
    expect(rows[0].verdict).toBeNull();
    expect(rows[0].status).toBe("completed");
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
