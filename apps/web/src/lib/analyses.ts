/**
 * One list of analyses, from the two endpoints that each held half of it.
 *
 * A report is a completed job's, or one a failed job kept and marked
 * incomplete. The console had a Jobs page and a Reports page
 * and the second was the first with one status filter already applied — same
 * sample, same link, different columns — so a reader who wanted "the run of
 * that file" had to guess which of the two pages knew about it. The search
 * palette listed both, and the dashboard listed the jobs a third time.
 *
 * `GET /jobs` knows the status and the timing; `GET /reports` knows the
 * verdict and the confidence. Joined on the job id, they are one row: what was
 * analysed, how the run ended, and what it concluded when it concluded
 * anything.
 */

import type { JobDTO, ReportSummaryDTO } from "@/lib/api";

export interface AnalysisRow {
  /** The job's id, which is also its route: `/analysis/{id}`. */
  id: string;
  sampleId: string;
  /** The filename, else a hash prefix, else the sample id's prefix. */
  sample: string;
  /** The sample's full SHA-256, when the job listing carried it. A row built
   *  from a report alone has none, and offers nothing to copy. */
  sha256: string | null;
  status: string;
  createdAt: string;
  durationSeconds: number | null;
  /** Present once the run produced a report; a running job has neither. */
  verdict: string | null;
  confidence: number | null;
  malwareCategory: string | null;
  /** The sentence a report kept from a failed run carries; `null` for a
   *  report of a completed run and for a run with no report. */
  incompleteReason: string | null;
}

/**
 * How a run names its sample, in one place.
 *
 * Every list picked its own precedence and three of them landed on the opaque
 * `sample_id`, so ten rows read identically.
 */
export function sampleLabel(job: {
  sample_filename?: string | null;
  sample_sha256?: string | null;
  sample_id: string;
}): string {
  return (
    job.sample_filename ||
    (job.sample_sha256 ? `${job.sample_sha256.slice(0, 16)}…` : "") ||
    job.sample_id.slice(0, 12)
  );
}

/**
 * The jobs, each carrying its report's verdict where it has one.
 *
 * Jobs lead: a run that has not finished is still an analysis and still
 * belongs on the list. A report whose job the page did not fetch is added at
 * the end rather than dropped — the two endpoints page independently, and a
 * verdict is not worth losing to an off-by-one page size.
 */
export function analysisRows(
  jobs: JobDTO[] | null | undefined,
  reports: ReportSummaryDTO[] | null | undefined,
): AnalysisRow[] {
  const byJob = new Map<string, ReportSummaryDTO>();
  for (const report of reports ?? []) byJob.set(report.job_id, report);

  const rows: AnalysisRow[] = (jobs ?? []).map((job) => {
    const report = byJob.get(job.id);
    byJob.delete(job.id);
    return {
      id: job.id,
      sampleId: job.sample_id,
      sample: sampleLabel(job),
      sha256: job.sample_sha256 || null,
      status: job.status,
      createdAt: job.created_at,
      durationSeconds: job.duration_seconds,
      verdict: report?.verdict ?? null,
      confidence: report?.overall_confidence ?? null,
      malwareCategory: report?.malware_category ?? null,
      incompleteReason: report?.incomplete_reason ?? null,
    };
  });

  for (const report of byJob.values()) {
    rows.push({
      id: report.job_id,
      sampleId: "",
      sample: report.sample_filename || report.job_id.slice(0, 12),
      sha256: null,
      // A report kept from a failed run is not a completed job's.
      status: report.incomplete_reason ? "failed" : "completed",
      createdAt: report.created_at,
      durationSeconds: null,
      verdict: report.verdict,
      confidence: report.overall_confidence,
      malwareCategory: report.malware_category,
      incompleteReason: report.incomplete_reason ?? null,
    });
  }

  /* Newest first, and sorted here rather than trusted from either endpoint:
   * the reports appended above have no place in the jobs order, so without
   * this a finished run could sit under older ones. A row whose timestamp
   * cannot be read sorts as the oldest, which is where a row nothing can date
   * belongs on a list read newest first. */
  return rows.sort((a, b) => time(b.createdAt) - time(a.createdAt));
}

/**
 * The dashboard's latest runs: exactly these jobs, each with its verdict.
 *
 * The same join as the full list, but the jobs are the whole answer: a report
 * whose job is not one of the latest few is somebody else's row, so it is not
 * appended the way the full list keeps it. A job whose report was not in the
 * page of reports asked for keeps a null verdict and is drawn by its status,
 * which is also what a run that has not finished looks like.
 */
export function latestRunRows(
  jobs: JobDTO[] | null | undefined,
  reports: ReportSummaryDTO[] | null | undefined,
): AnalysisRow[] {
  const wanted = new Set((jobs ?? []).map((job) => job.id));
  return analysisRows(jobs, reports).filter((row) => wanted.has(row.id));
}

/** An ISO timestamp as a number, or 0 for one that cannot be read. */
function time(iso: string | null | undefined): number {
  const at = new Date(iso ?? "").getTime();
  return Number.isNaN(at) ? 0 : at;
}

/** The statuses the list filters by, in the order they are offered. */
export const STATUS_FILTERS = [
  "all",
  "completed",
  "running",
  "pending",
  "failed",
  "cancelled",
] as const;
export type StatusFilter = (typeof STATUS_FILTERS)[number];

/** A `?status=` from the URL, or "all" when it names nothing this list has. */
export function statusFilterFrom(value: string | null | undefined): StatusFilter {
  const wanted = (value ?? "").toLowerCase();
  return (STATUS_FILTERS as readonly string[]).includes(wanted)
    ? (wanted as StatusFilter)
    : "all";
}

export function countByStatus(rows: AnalysisRow[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const row of rows) counts[row.status] = (counts[row.status] ?? 0) + 1;
  return counts;
}
