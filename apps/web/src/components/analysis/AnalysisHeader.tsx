"use client";

import { forwardRef, useId, useMemo, useState } from "react";
import { MessageSquare, Moon, Sun } from "lucide-react";
import type { JobDTO, ReportDetailDTO } from "@/lib/api";
import CopyButton from "@/components/ui/CopyButton";
import ExportMenu from "@/components/ui/ExportMenu";
import { buttonClass } from "@/components/ui/Button";
import { Tag } from "@/components/ui/Pill";
import { reportExportGroups } from "@/components/ui/exportActions";
import { formatBytes, formatDateTime, formatDuration, truncateMiddle } from "@/lib/report-utils";
import { jobFinished } from "@/lib/runFailure";
import { statusTone } from "@/lib/status";
import { verdictLabel, verdictTone } from "@/lib/verdict";
import { canAskFollowUp } from "./followUps";
import ConfidenceMeter from "./ConfidenceMeter";
import {
  capChips,
  exportBaseName,
  fileKind,
  fileName,
  headerTags,
  otherHashes,
  verdictConfidence,
  verdictSentence,
  type VerdictConfidence,
} from "./overview";
import type { UiTheme } from "./theme";

/**
 * The analysis header: what the analysis concluded and what the file is, in
 * the first glance, on every tab.
 *
 * One bold element, the verdict line: the verdict's word in its colour and
 * the five-step confidence meter. Under it the family as the page's heading
 * (the file's name when no family was identified), one plain sentence of
 * what the sample is, and a quiet line of file identity: the SHA-256 with
 * copy and the other hashes on demand, type and size, how the run ended and
 * when. At most three classification tags, the rest behind "more". The
 * page's actions (Chat, Export, theme) sit on the verdict line's right.
 *
 * The header scrolls away with the page; the sticky bar under it takes the
 * verdict in short (`CompactVerdict`) so the page never changes height under
 * the reader. Until the job and its report have loaded it draws a neutral
 * placeholder, never "no verdict" or a fallback name that would read as a
 * result.
 */

const MAX_TAGS = 3;

export interface HeaderFacts {
  verdict: string | null;
  verdictWord: string;
  confidence: VerdictConfidence;
  family: string | null;
  name: string;
  askable: boolean;
}

/** What the header and the compact bar both say. */
export function headerFacts(report: ReportDetailDTO | null, job: JobDTO | null): HeaderFacts {
  const mr = report?.malware_report ?? null;
  const verdict = report?.verdict ?? mr?.verdict ?? null;
  return {
    verdict,
    verdictWord: report
      ? verdictLabel(verdict)
      : job && !jobFinished(job.status)
        ? "Analysis running"
        : "No report stored",
    /* The confidence the API publishes with the verdict. A verdict it
     * published without one (a fallback reading) is "not assessed", never the
     * structured report's own number. */
    confidence: verdictConfidence(
      verdict,
      report && report.overall_confidence !== undefined ? report.overall_confidence : mr?.overall_confidence,
    ),
    family: mr?.attribution?.family ?? null,
    name: fileName(report, job),
    /* A question is answered from what a finished run stored. */
    askable: Boolean(report) && canAskFollowUp(job?.status ?? ""),
  };
}

export default function AnalysisHeader({
  jobId,
  job,
  report,
  loading,
  theme,
  onTheme,
  chat,
}: {
  jobId: string;
  job: JobDTO | null;
  report: ReportDetailDTO | null;
  /** True until the job, and the report of a finished job, have been read. */
  loading: boolean;
  theme: UiTheme;
  onTheme: (t: UiTheme) => void;
  /** The Chat button, drawn by the frame that owns the drawer. */
  chat?: React.ReactNode;
}) {
  const mr = report?.malware_report ?? null;
  const facts = headerFacts(report, job);
  const tone = verdictTone(facts.verdict);
  const [allTags, setAllTags] = useState(false);
  const [hashesOpen, setHashesOpen] = useState(false);
  const hashesId = useId();
  const hashes = otherHashes(mr);
  const sentence = verdictSentence(mr, report?.malware_category);
  const tags = headerTags(mr, report?.malware_category);
  const { shown, more } = capChips(tags, MAX_TAGS);
  const visibleTags = allTags ? tags : shown;
  const sha256 = mr?.identity?.hashes?.sha256 || job?.sample_sha256 || "";
  const status = job?.status ?? "";
  const groups = useMemo(
    () => (report ? reportExportGroups(report.id, mr, exportBaseName(sha256, jobId), report.stix_bundle) : []),
    [report, mr, sha256, jobId],
  );
  const analyzedIso = report?.created_at ?? job?.created_at;
  /* A name made of the hash says nothing the hash beside it does not. */
  const nameAddsNothing = Boolean(sha256) && facts.name.toLowerCase().startsWith(sha256.toLowerCase());
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
      <section className="px-4 pb-4 pt-4 sm:px-6" aria-label="Analysis summary" aria-busy="true">
        <div className="flex items-center gap-4">
          <div className="min-w-0 flex-1 space-y-2">
            <p className="text-sm text-text-muted">Loading the analysis…</p>
            <div aria-hidden="true" className="h-6 w-56 max-w-full rounded bg-bg-active" />
            <div aria-hidden="true" className="h-3 w-80 max-w-full rounded bg-bg-active" />
          </div>
          {themeButton}
        </div>
      </section>
    );
  }

  return (
    <section className="px-4 pb-4 pt-4 sm:px-6" aria-label="Analysis summary">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 sm:gap-x-5">
        <p className={`flex items-center gap-2 text-base font-semibold ${tone.text}`} data-testid="verdict-word">
          <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full" style={{ background: tone.fill }} />
          {facts.verdictWord}
        </p>
        {/* On a phone the meter takes the line under the verdict, so the
            verdict and the actions share the first. */}
        {report && (
          <span className="order-last w-full sm:order-none sm:w-auto">
            <ConfidenceMeter confidence={facts.confidence} />
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          {facts.askable && chat}
          {report && <ExportMenu groups={groups} />}
          {themeButton}
        </div>
      </div>

      <h1 className="mt-2 break-words text-2xl font-semibold text-text-primary" title={facts.family ? undefined : facts.name}>
        {facts.family ?? (nameAddsNothing ? "Family not identified" : facts.name)}
      </h1>
      {(sentence || (!facts.family && !nameAddsNothing)) && (
        <p className="mt-1 max-w-[72ch] text-sm text-text-secondary">
          {sentence || "Family not identified."}
        </p>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-1.5 text-xs text-text-secondary">
        {!nameAddsNothing && facts.family && (
          <span className="max-w-full truncate" title={facts.name}>
            {facts.name}
          </span>
        )}
        {sha256 && (
          <span className="inline-flex flex-wrap items-center gap-1.5">
            <span className="sr-only">SHA-256</span>
            <code className="whitespace-nowrap font-mono text-text-primary" title={sha256}>
              {truncateMiddle(sha256, 20)}
            </code>
            <CopyButton value={sha256} what={`SHA-256 of ${facts.name}`} label="copy" />
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
        {mr?.identity && (
          <span>
            {fileKind(mr.identity)}
            {mr.identity.file_size_bytes > 0 && <>, {formatBytes(mr.identity.file_size_bytes)}</>}
          </span>
        )}
        {status && (
          <span>
            <span className={statusTone(status).text}>{status.charAt(0).toUpperCase() + status.slice(1)}</span>
            {job?.duration_seconds != null && <> in {formatDuration(job.duration_seconds)}</>}
          </span>
        )}
        {analyzedIso && <span>Analyzed {formatDateTime(analyzedIso)}</span>}
        {visibleTags.length > 0 && (
          <span className="inline-flex flex-wrap items-center gap-1.5">
            <span className="sr-only">Classified as</span>
            {visibleTags.map((c) => (
              <Tag key={c}>{c}</Tag>
            ))}
            {more > 0 && (
              <button
                type="button"
                aria-expanded={allTags}
                onClick={() => setAllTags((v) => !v)}
                className="rounded px-1 text-[11px] text-accent-strong hover:underline"
              >
                {allTags ? "Fewer" : `${more} more`}
                {!allTags && <span className="sr-only"> classifications</span>}
              </button>
            )}
          </span>
        )}
      </div>
      {hashesOpen && (
        <dl id={hashesId} className="mt-3 grid max-w-3xl gap-1.5 rounded-md border border-border-light bg-bg-deep p-3 text-xs">
          {hashes.map((r) => (
            <div key={r.label} className="flex items-start gap-2">
              <dt className="w-20 shrink-0 text-text-muted">{r.label}</dt>
              <dd className="min-w-0 flex-1 break-all font-mono text-text-primary">{r.value}</dd>
              <CopyButton value={r.value} what={`${r.label} of ${facts.name}`} label="copy" />
            </div>
          ))}
        </dl>
      )}
    </section>
  );
}

/**
 * The verdict in short, for the sticky bar once the header has scrolled
 * away: the verdict's word in its colour, the meter's steps, the family.
 */
export function CompactVerdict({ facts }: { facts: HeaderFacts }) {
  const tone = verdictTone(facts.verdict);
  return (
    <span className="flex min-w-0 items-center gap-2 text-sm" data-testid="compact-verdict">
      <span className={`flex shrink-0 items-center gap-1.5 font-semibold ${tone.text}`}>
        <span aria-hidden="true" className="h-2 w-2 rounded-full" style={{ background: tone.fill }} />
        {facts.verdictWord}
      </span>
      <span className="hidden shrink-0 md:inline-flex">
        <ConfidenceMeter confidence={facts.confidence} compact />
      </span>
      <span className="hidden min-w-0 truncate text-text-primary lg:inline" title={facts.family ?? facts.name}>
        {facts.family ?? facts.name}
      </span>
    </span>
  );
}

/** The button that opens the chat drawer. */
export const ChatButton = forwardRef<
  HTMLButtonElement,
  { open: boolean; onClick: (opener: HTMLElement) => void; controls: string; iconOnly?: boolean }
>(function ChatButton({ open, onClick, controls, iconOnly = false }, ref) {
  return (
    <button
      ref={ref}
      type="button"
      data-variant="secondary"
      aria-expanded={open}
      aria-controls={controls}
      aria-label={iconOnly ? "Chat about this analysis" : undefined}
      onClick={(e) => onClick(e.currentTarget)}
      className={buttonClass("secondary", "sm")}
    >
      <MessageSquare aria-hidden="true" className="h-3.5 w-3.5" />
      {/* On a phone the word is the button's name only, so the verdict and
          the actions keep one line. */}
      {!iconOnly && <span className="sr-only sm:not-sr-only">Chat</span>}
    </button>
  );
});
