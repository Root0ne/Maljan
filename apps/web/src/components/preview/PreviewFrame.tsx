"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { usePathname } from "next/navigation";
import { api } from "@/lib/api";
import type { JobDTO, ReportDetailDTO } from "@/lib/api";
import { getErrorMessage, isApiStatus } from "@/lib/errors";
import { jobFinished } from "@/lib/runFailure";
import Tabs, { activeTabKey, type TabItem } from "@/components/ui/Tabs";
import Drawer from "@/components/ui/Drawer";
import AnalysisHeader from "./AnalysisHeader";
import EvidenceDetail, { type EvidenceSubject } from "./EvidenceDetail";
import { PREVIEW_TABS, previewHref, remarks, tabCounts } from "./overview";
import { useUiTheme } from "./theme";

/**
 * The frame of the new analysis page: the data, the sticky header, the
 * remarks, the six tabs and the evidence drawer every tab opens.
 *
 * It reads the same two answers today's page reads (`getJob`, then
 * `getReportByJobId` once the job is finished) and polls while the job runs.
 * A tab under it reads them with `usePreview`, and opens the drawer with
 * `showEvidence`.
 */

const POLL_MS = 3_000;

interface PreviewCtx {
  jobId: string;
  job: JobDTO | null;
  report: ReportDetailDTO | null;
  loading: boolean;
  error: string | null;
  /** Open the drawer on `subject`; `opener` is the control clicked, which
   *  gets focus back when the drawer closes. */
  showEvidence: (subject: EvidenceSubject, opener?: HTMLElement | null) => void;
}

const Ctx = createContext<PreviewCtx>({
  jobId: "",
  job: null,
  report: null,
  loading: true,
  error: null,
  showEvidence: () => {},
});

export function usePreview(): PreviewCtx {
  return useContext(Ctx);
}

export default function PreviewFrame({ jobId, children }: { jobId: string; children: ReactNode }) {
  const pathname = usePathname() ?? "";
  const [job, setJob] = useState<JobDTO | null>(null);
  const [report, setReport] = useState<ReportDetailDTO | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subject, setSubject] = useState<EvidenceSubject | null>(null);
  const [opener, setOpener] = useState<HTMLElement | null>(null);
  const [compact, setCompact] = useState(false);
  const [theme, setTheme] = useUiTheme();

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const load = async () => {
      try {
        const j = await api.getJob(jobId);
        if (cancelled) return;
        setJob(j);
        if (jobFinished(j.status)) {
          try {
            const r = await api.getReportByJobId(jobId);
            if (!cancelled) setReport(r);
          } catch (err) {
            // A finished job without a report is an answer, not an outage.
            if (!cancelled && !isApiStatus(err, 404)) setError(`Could not read the report: ${getErrorMessage(err)}`);
          }
        } else {
          timer = setTimeout(() => void load(), POLL_MS);
        }
      } catch (err) {
        if (!cancelled) {
          setError(
            isApiStatus(err, 404)
              ? "There is no analysis with this id."
              : `Could not read the analysis: ${getErrorMessage(err)}`,
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [jobId]);

  // The header folds to one row once the page scrolls under it.
  useEffect(() => {
    const main = document.getElementById("main-content");
    if (!main) return;
    // Two thresholds, so the header's own change of height cannot flip it
    // back: it folds past 72 px and opens again only near the top.
    const onScroll = () =>
      setCompact((was) => (was ? main.scrollTop > 8 : main.scrollTop > 72));
    main.addEventListener("scroll", onScroll, { passive: true });
    return () => main.removeEventListener("scroll", onScroll);
  }, []);

  const mr = report?.malware_report ?? null;
  const counts = useMemo(() => tabCounts(mr), [mr]);
  const running = job !== null && !jobFinished(job.status);
  const tabs: TabItem[] = PREVIEW_TABS.map((t) => ({
    key: t.key,
    label: t.label,
    href: previewHref(jobId, t),
    count: counts[t.key],
  }));
  /* Overview's href is every other tab's parent, so the longest match picks
   * the tab; an exact match on the base is Overview. */
  const active = activeTabKey(tabs, pathname);
  const notes = remarks(report);
  const showEvidence = useCallback((s: EvidenceSubject, from?: HTMLElement | null) => {
    setOpener(from ?? null);
    setSubject(s);
  }, []);
  const closeEvidence = useCallback(() => setSubject(null), []);

  const ctx = useMemo<PreviewCtx>(
    () => ({ jobId, job, report, loading, error, showEvidence }),
    [jobId, job, report, loading, error, showEvidence],
  );

  return (
    <Ctx.Provider value={ctx}>
      {/* `-m-6` undoes the shell's padding so the sticky header spans the
          column and meets the top edge; the content restores it. The sticky
          line is the scroller's padding edge, 24 px down, hence `-top-6`:
          with `top-0` the header was pushed down by the padding it had just
          undone. Scroll anchoring is off for the same reason as the two
          thresholds below: folding the header must not move the scroll
          position the fold was decided on. */}
      <div className="-m-6 min-h-full bg-bg-deep text-text-primary [overflow-anchor:none]" data-testid="analysis-preview">
        <div className="sticky -top-6 z-30 border-b border-border bg-bg-surface">
          <AnalysisHeader
            jobId={jobId}
            job={job}
            report={report}
            loading={loading}
            compact={compact}
            theme={theme}
            onTheme={setTheme}
          />
          {!running && !loading && (
            <div className="px-4 sm:px-6">
              <Tabs tabs={tabs} active={active} label="Analysis sections" />
            </div>
          )}
        </div>
        {notes.length > 0 && (
          <section
            aria-label="Remarks"
            className="border-b border-status-orange/30 bg-status-orange/10 px-4 py-2 text-xs text-text-primary sm:px-6"
          >
            <ul className="space-y-0.5">
              {notes.map((n) => (
                <li key={n.text} title={n.detail ?? undefined}>
                  {n.text}
                </li>
              ))}
            </ul>
          </section>
        )}
        <div className="mx-auto max-w-[88rem] px-4 py-5 sm:px-6">
          {error ? (
            <div role="alert" className="rounded border border-status-red/30 bg-status-red/10 px-3 py-2 text-sm text-status-red">
              {error}
            </div>
          ) : loading ? (
            <p className="text-sm text-text-muted">Loading the analysis…</p>
          ) : running ? (
            <p className="text-sm text-text-secondary">
              The analysis is still running. This page fills in when it finishes.
            </p>
          ) : (
            children
          )}
        </div>
      </div>
      <Drawer open={subject !== null} title={subject?.title ?? ""} onClose={closeEvidence} returnFocusTo={opener}>
        {subject && <EvidenceDetail jobId={jobId} subject={subject} />}
      </Drawer>
    </Ctx.Provider>
  );
}
