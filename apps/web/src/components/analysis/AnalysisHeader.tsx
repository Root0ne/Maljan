"use client";

import { useId, useMemo, useState, useSyncExternalStore } from "react";
import { Moon, Sun } from "lucide-react";
import type { JobDTO, ReportDetailDTO } from "@/lib/api";
import CopyButton from "@/components/ui/CopyButton";
import ExportMenu from "@/components/ui/ExportMenu";
import { buttonClass } from "@/components/ui/Button";
import { Tag } from "@/components/ui/Pill";
import { reportExportGroups } from "@/components/ui/exportActions";
import { formatBytes, formatDateTime, formatDuration, truncateMiddle } from "@/lib/report-utils";
import { jobFinished } from "@/lib/runFailure";
import { statusTone } from "@/lib/status";
import { verdictBucket, verdictLabel, verdictTone } from "@/lib/verdict";
import AskMenu from "./AskMenu";
import { canAskFollowUp } from "./followUps";
import ConfidenceGauge from "./ConfidenceGauge";
import {
  CONFIDENCE_WHY,
  capChips,
  classificationChips,
  exportBaseName,
  fileName,
  otherHashes,
  verdictConfidence,
} from "./overview";
import type { UiTheme } from "./theme";

/**
 * The analysis header: what the sample is and what the analysis concluded,
 * in the first glance, on every tab.
 *
 * Left to right: the verdict as a coloured strip with its word, the
 * verdict's confidence as a ring (no score: the report has none), the file and its family
 * with up to five classification chips (the rest behind "+N"). Under it the
 * file facts and the SHA-256 with copy; the other hashes open on demand.
 * On the right the page's actions: Export and Ask. Once the page scrolls the
 * second row folds away; on a narrow screen the whole header folds to one
 * row (verdict, confidence, file name, Export, Ask) so the content keeps the
 * screen. Until the job and its report have loaded it draws a neutral
 * placeholder, never "no verdict" or a fallback name that would read as a
 * result.
 */

const NARROW = "(max-width: 639px)";

function subscribeNarrow(onChange: () => void): () => void {
  if (typeof window.matchMedia !== "function") return () => {};
  const media = window.matchMedia(NARROW);
  media.addEventListener("change", onChange);
  return () => media.removeEventListener("change", onChange);
}

/** Whether the viewport is phone-narrow (below Tailwind's `sm`). */
function useNarrow(): boolean {
  return useSyncExternalStore(
    subscribeNarrow,
    () => typeof window.matchMedia === "function" && window.matchMedia(NARROW).matches,
    () => false,
  );
}

const STRIP: Record<string, string> = {
  malicious: "bg-status-red/15 border-status-red",
  suspicious: "bg-status-orange/15 border-status-orange",
  benign: "bg-status-green/15 border-status-green",
  unknown: "bg-bg-active border-text-muted",
};

export default function AnalysisHeader({
  jobId,
  job,
  report,
  loading,
  compact,
  theme,
  onTheme,
}: {
  jobId: string;
  job: JobDTO | null;
  report: ReportDetailDTO | null;
  /** True until the job, and the report of a finished job, have been read. */
  loading: boolean;
  compact: boolean;
  theme: UiTheme;
  onTheme: (t: UiTheme) => void;
}) {
  const mr = report?.malware_report ?? null;
  const verdict = report?.verdict ?? mr?.verdict ?? null;
  const bucket = verdictBucket(verdict);
  const tone = verdictTone(verdict);
  /* The confidence the API publishes with the verdict. A verdict it
   * published without one (a fallback reading) is "not assessed", never the
   * structured report's own number. */
  const confidence = verdictConfidence(
    verdict,
    report && report.overall_confidence !== undefined ? report.overall_confidence : mr?.overall_confidence,
  );
  const chips = classificationChips(mr, report?.malware_category);
  const [allChips, setAllChips] = useState(false);
  const [hashesOpen, setHashesOpen] = useState(false);
  const hashesId = useId();
  const hashes = otherHashes(mr);
  const { shown, more } = capChips(chips, 5);
  const visibleChips = allChips ? chips : shown;
  const family = mr?.attribution?.family ?? null;
  const name = fileName(report, job);
  const sha256 = mr?.identity?.hashes?.sha256 || job?.sample_sha256 || "";
  const status = job?.status ?? "";
  const groups = useMemo(
    () => (report ? reportExportGroups(report.id, mr, exportBaseName(sha256, jobId), report.stix_bundle) : []),
    [report, mr, sha256, jobId],
  );
  const narrow = useNarrow();
  /* A question is answered from what a finished run stored. */
  const askable = Boolean(report) && canAskFollowUp(status);
  const analyzedIso = report?.created_at ?? job?.created_at;
  const verdictWord = report
    ? verdictLabel(verdict)
    : job && !jobFinished(job.status)
      ? "Analysis running"
      : "No report stored";
  const themeButton = (
    <button
      type="button"
      onClick={() => onTheme(theme === "dark" ? "light" : "dark")}
      aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      className={buttonClass("ghost", "sm")}
    >
      {theme === "dark" ? <Sun aria-hidden="true" className="h-4 w-4" /> : <Moon aria-hidden="true" className="h-4 w-4" />}
    </button>
  );

  if (loading) {
    return (
      <section className="px-4 pb-3 pt-3 sm:px-6" aria-label="Analysis summary" aria-busy="true">
        <div className="flex items-center gap-4">
          <div aria-hidden="true" className="h-10 w-28 rounded bg-bg-active" />
          <div aria-hidden="true" className="h-10 w-10 rounded-full bg-bg-active" />
          <div className="min-w-0 flex-1 space-y-2">
            <p className="text-sm text-text-muted">Loading the analysis…</p>
            <div aria-hidden="true" className="h-3 w-48 max-w-full rounded bg-bg-active" />
          </div>
          {themeButton}
        </div>
      </section>
    );
  }

  if (compact && narrow) {
    return (
      <section className="px-4 py-2" aria-label="Analysis summary" data-folded="true">
        <div className="flex items-center gap-2">
          <span className={`shrink-0 border-l-4 px-2 py-1 text-sm font-semibold ${STRIP[bucket]} ${tone.text}`}>
            {verdictWord}
          </span>
          {report && <ConfidenceGauge confidence={confidence} verdict={verdict} size="sm" />}
          <span className="min-w-0 flex-1 truncate text-sm text-text-primary" title={name}>
            {name}
          </span>
          {report && <ExportMenu groups={groups} />}
          {askable && <AskMenu jobId={jobId} />}
        </div>
      </section>
    );
  }

  return (
    <section className="px-4 pt-3 sm:px-6" aria-label="Analysis summary">
      <div className="flex flex-wrap items-start gap-x-4 gap-y-3">
        <div className={`flex items-center self-stretch border-l-4 px-3 ${STRIP[bucket]}`}>
          <span className={`text-base font-semibold ${tone.text}`}>{verdictWord}</span>
        </div>
        {report && <ConfidenceGauge confidence={confidence} verdict={verdict} />}
        <div className="min-w-0 flex-1 basis-64">
          <h1 className="truncate text-lg font-semibold text-text-primary" title={name}>
            {name}
          </h1>
          <div className="mt-1 flex flex-wrap items-center gap-1.5">
            <span className="text-sm text-text-secondary">{family ?? "Family not identified"}</span>
            {visibleChips.map((c) => (
              <Tag key={c}>{c}</Tag>
            ))}
            {more > 0 && (
              <button
                type="button"
                aria-expanded={allChips}
                onClick={() => setAllChips((v) => !v)}
                className="rounded px-1 text-[11px] text-accent-strong hover:underline"
              >
                {allChips ? "Show fewer" : `+${more}`}
                {!allChips && <span className="sr-only"> more classifications</span>}
              </button>
            )}
          </div>
        </div>
        <div className="ml-auto flex items-center gap-2">
          {report && <ExportMenu groups={groups} />}
          {askable && <AskMenu jobId={jobId} />}
          {themeButton}
        </div>
      </div>

      {!compact && (
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1.5 pb-2 text-xs text-text-secondary">
          {report && <span data-testid="confidence-why">{CONFIDENCE_WHY}</span>}
          {mr?.identity && (
            <span>
              {mr.identity.file_type}
              {mr.identity.file_size_bytes > 0 && <>, {formatBytes(mr.identity.file_size_bytes)}</>}
            </span>
          )}
          {sha256 && (
            <span className="inline-flex flex-wrap items-center gap-1.5">
              <span className="whitespace-nowrap text-text-muted">SHA-256</span>
              <code className="whitespace-nowrap font-mono text-text-primary" title={sha256}>
                {truncateMiddle(sha256, 24)}
              </code>
              <CopyButton value={sha256} what={`SHA-256 of ${name}`} label="copy" />
              {hashes.length > 0 && (
                <button
                  type="button"
                  aria-expanded={hashesOpen}
                  aria-controls={hashesOpen ? hashesId : undefined}
                  onClick={() => setHashesOpen((v) => !v)}
                  className="whitespace-nowrap rounded px-1 text-[11px] text-accent-strong hover:underline"
                >
                  {hashesOpen ? "Hide hashes" : "All hashes"}
                </button>
              )}
            </span>
          )}
          {status && (
            <span className={statusTone(status).text}>
              {status.charAt(0).toUpperCase() + status.slice(1)}
              {job?.duration_seconds != null && <span className="text-text-secondary">, {formatDuration(job.duration_seconds)}</span>}
            </span>
          )}
          {analyzedIso && <span>Analyzed {formatDateTime(analyzedIso)}</span>}
        </div>
      )}
      {!compact && hashesOpen && (
        <dl id={hashesId} className="mb-2 grid gap-1.5 rounded-md border border-border-light bg-bg-deep p-3 text-xs">
          {hashes.map((r) => (
            <div key={r.label} className="flex items-start gap-2">
              <dt className="w-20 shrink-0 text-text-muted">{r.label}</dt>
              <dd className="min-w-0 flex-1 break-all font-mono text-text-primary">{r.value}</dd>
              <CopyButton value={r.value} what={`${r.label} of ${name}`} label="copy" />
            </div>
          ))}
        </dl>
      )}
      {compact && <div className="pb-2" />}
    </section>
  );
}
