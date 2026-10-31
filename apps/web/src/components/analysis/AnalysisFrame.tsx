"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/lib/api";
import type { ReportDetailDTO, JobDTO } from "@/lib/api";
import FailureNote from "@/components/ui/FailureNote";
import Drawer from "@/components/ui/Drawer";
import Tabs, { activeTabKey, type TabItem } from "@/components/ui/Tabs";
import {
  hydrateRunTranscript,
  setRunRoster,
  setRunStoredStages,
} from "@/lib/runStore";
import { useRun } from "@/lib/useRun";
import { jobFailure, jobFinished } from "@/lib/runFailure";
import { AnalysisContext, type AnalysisCtx } from "./AnalysisContext";
import AnalysisHeader from "./AnalysisHeader";
import EvidenceDetail, { type EvidenceSubject } from "./EvidenceDetail";
import { ANALYSIS_TABS, RUNNING_TABS, analysisHref, remarks, tabCounts } from "./overview";
import {
  POLL_INTERVAL_MS,
  pollDelay,
  pollFailure,
  pollNotice,
  reportFetchError,
} from "./polling";
import { useUiTheme } from "./theme";

/**
 * The frame of one analysis: the data, the sticky header, the remarks, the
 * six tabs and the evidence drawer every tab opens.
 *
 * It polls `getJob` until the job has finished, then reads the report; the
 * live feed comes from the run store (`useRun`). A tab under it reads both
 * with `useReport`, and opens the drawer with `showEvidence`.
 */
export default function AnalysisFrame({ id, children }: { id: string; children: React.ReactNode }) {
  const pathname = usePathname() ?? "";

  const [report, setReport] = useState<ReportDetailDTO | null>(null);
  const [job, setJob] = useState<JobDTO | null>(null);
  const [loading, setLoading] = useState(true);
  const [apiAvailable, setApiAvailable] = useState(false);
  const [apiError, setApiError] = useState<string | null>(null);
  /* A 404 from `GET /jobs/{id}` is an answer, not
   * an outage. Kept apart from `apiError` so the page can say the job does not
   * exist instead of blaming the backend for a reply the backend gave. */
  const [notFound, setNotFound] = useState(false);
  const [reportError, setReportError] = useState<string | null>(null);
  /* Polling ended on a refusal the API will repeat (`pollFailure`). */
  const [pollStopped, setPollStopped] = useState(false);
  const [enrichmentToast, setEnrichmentToast] = useState<string | null>(null);
  const refetchRef = useRef<(() => Promise<void>) | null>(null);
  const [subject, setSubject] = useState<EvidenceSubject | null>(null);
  const [opener, setOpener] = useState<HTMLElement | null>(null);
  const [compact, setCompact] = useState(false);
  const [theme, setTheme] = useUiTheme();

  useEffect(() => {
    let cancelled = false;
    let failures = 0;

    async function refetchReport(terminal = false) {
      if (cancelled) return;
      try {
        const r = await api.getReportByJobId(id);
        if (cancelled) return;
        setReport(r);
        setReportError(null);
      } catch (err) {
        // While the job is still running a missing report is expected, and a
        // finished run's 404 is a run that wrote none — an absence the tabs
        // say as such. Only another failure is a read error
        // (`reportFetchError`).
        if (!cancelled) {
          const message = reportFetchError(err, terminal);
          if (message) setReportError(message);
        }
      }
    }
    refetchRef.current = refetchReport;

    async function fetchAll() {
      try {
        const j = await api.getJob(id);
        if (cancelled) return;
        setJob(j);
        setApiAvailable(true);
        setApiError(null);
        failures = 0;

        /* A cancelled run has ended as surely as a failed one, and it may
         * have kept a partial report: polling stops and the report is read. */
        if (jobFinished(j.status)) {
          await refetchReport(true);
          if (!cancelled) setLoading(false);
          return; // stop polling
        }

        // Job still running — schedule next poll
        if (!cancelled) setLoading(false);
        setTimeout(() => { if (!cancelled) fetchAll(); }, POLL_INTERVAL_MS);
      } catch (err) {
        // Report *why* the API call failed instead of only
        // the generic "could not connect" banner, and keep polling: one
        // failed poll used to end the polling for good (`polling.ts`).
        if (!cancelled) {
          const failure = pollFailure(err);
          if (failure.kind === "not-found") setNotFound(true);
          else if (failure.kind === "stop") {
            // A refusal: asking again will not change it.
            setApiError(failure.message);
            setPollStopped(true);
          } else {
            setApiError(failure.message);
            const delay = pollDelay(failures, failure.retryAfterMs);
            failures += 1;
            setTimeout(() => { if (!cancelled) fetchAll(); }, delay);
          }
          setLoading(false);
        }
      }
    }

    fetchAll();
    return () => { cancelled = true; };
  }, [id]);

  /* The run's feed, from the store that owns it.
   *
   * Nothing is subscribed for a job the API has already said does not exist:
   * the page used to retry the handshake five times against a confirmed 404.
   * The subscription also waits for that first answer rather than dialling on
   * mount, which is the only way "the job exists" can be known before the
   * dial. */
  const run = useRun(loading || notFound ? null : id);
  const events = run.events;

  /* What the frame itself needs from the feed: a report to refetch when
   * enrichment lands or when the run finishes, without waiting for the poll
   * to come back round. */
  const lastEventCursor = useRef(0);
  /* Which enrichment is news.
   *
   * The store folds the whole recorded feed in one commit, so an
   * `enrichment_complete` in it happened hours ago: worth one refetch, never
   * worth announcing in the present tense every time the run is opened. What
   * separates the two is the newest event this reader already held — the
   * publisher's own timestamp on both sides of the comparison, so no clock but
   * the API's is ever consulted.
   *
   * The first batch is the recorded feed by construction, and its newest
   * timestamp becomes the watermark everything after it is read against. */
  const newestHeld = useRef<string | null>(null);
  useEffect(() => {
    if (events.length <= lastEventCursor.current) return;
    const firstBatch = newestHeld.current === null;
    const watermark = newestHeld.current;
    for (let i = lastEventCursor.current; i < events.length; i++) {
      const e = events[i];
      if (e.type !== "enrichment_complete" && e.type !== "completed") continue;
      refetchRef.current?.();
      if (e.type !== "enrichment_complete") continue;
      // `ts` is non-optional on the wire; an empty or unparseable one falls
      // back to the batch, which is the same answer the watermark would give.
      const alreadyHappened =
        firstBatch || !e.ts || (watermark !== null && e.ts <= watermark);
      if (alreadyHappened) continue;
      setEnrichmentToast("Threat intel enrichment finished. Report refreshed.");
      setTimeout(() => setEnrichmentToast(null), 5000);
    }
    for (let i = lastEventCursor.current; i < events.length; i++) {
      const ts = events[i].ts;
      if (ts && (newestHeld.current === null || ts > newestHeld.current)) {
        newestHeld.current = ts;
      }
    }
    // A batch whose every event is unstamped still has to move the feed off
    // "nothing held yet", or the next batch would read as the first one.
    if (newestHeld.current === null) newestHeld.current = "";
    lastEventCursor.current = events.length;
  }, [events]);

  /* Everything the store cannot learn from the feed alone: the roster a job
   * carries for a reader who opens it after the fact, the stage rollup that
   * knows about stages the run has not reached, and the recorded conversation
   * of a run whose feed predates the event recording. */
  useEffect(() => {
    if (job?.roster) setRunRoster(id, job.roster);
  }, [id, job?.roster]);

  useEffect(() => {
    setRunStoredStages(id, report?.run_summary?.stages ?? null);
  }, [id, report?.run_summary?.stages]);

  useEffect(() => {
    hydrateRunTranscript(id, report?.transcript);
  }, [id, report?.transcript]);

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

  const showEvidence = useCallback((s: EvidenceSubject, from?: HTMLElement | null) => {
    setOpener(from ?? null);
    setSubject(s);
  }, []);
  const closeEvidence = useCallback(() => setSubject(null), []);

  const mr = report?.malware_report ?? null;
  const counts = useMemo(() => tabCounts(mr), [mr]);
  /* While the job runs only Overview, which says how far it has got, and
   * Evidence, which holds the live discussion, have anything to show; the
   * counts wait for the report. */
  const running = job !== null && !jobFinished(job.status);
  const tabs: TabItem[] = ANALYSIS_TABS.filter((t) => !running || RUNNING_TABS.has(t.key)).map((t) => ({
    key: t.key,
    label: t.label,
    href: analysisHref(id, t.key),
    count: running ? null : counts[t.key],
  }));
  /* Overview's href is every other tab's parent, so the longest match picks
   * the tab; an exact match on the base is Overview. */
  const active = activeTabKey(tabs, pathname);
  const notes = remarks(report, job);
  /* What a failed run says about itself: the worker's own sentence and the id
   * the log entries holding the traceback are filed under. */
  const failure = jobFailure(job?.status, job?.error_message);
  const pollBanner = pollNotice(apiError, apiAvailable, pollStopped);

  const ctx = useMemo<AnalysisCtx>(
    () => ({ jobId: id, job, report, loading, reportError, showEvidence }),
    [id, job, report, loading, reportError, showEvidence],
  );

  if (notFound) {
    return (
      <div className="bg-bg-surface border border-border rounded p-8 text-center">
        <h1 className="text-lg font-semibold text-text-primary mb-1">Job not found</h1>
        <p className="text-sm text-text-secondary mb-4">
          No analysis job exists with the id <code className="font-mono">{id}</code>.
        </p>
        <Link href="/jobs" className="text-sm text-accent-strong hover:underline">
          Back to jobs
        </Link>
      </div>
    );
  }

  return (
    <AnalysisContext.Provider value={ctx}>
      {/* `-m-6` undoes the shell's padding so the sticky header spans the
          column and meets the top edge; the content restores it. The sticky
          line is the scroller's padding edge, 24 px down, hence `-top-6`.
          Scroll anchoring is off so folding the header cannot move the
          scroll position the fold was decided on. */}
      <div className="-m-6 min-h-full bg-bg-deep text-text-primary [overflow-anchor:none]" data-testid="analysis-page">
        <div className="sticky -top-6 z-30 border-b border-border bg-bg-surface">
          <AnalysisHeader
            jobId={id}
            job={job}
            report={report}
            loading={loading}
            compact={compact}
            theme={theme}
            onTheme={setTheme}
          />
          {!loading && (
            <div className="px-4 sm:px-6">
              <Tabs tabs={tabs} active={active} label="Analysis sections" />
            </div>
          )}
        </div>
        {(notes.length > 0 || failure) && (
          <section
            aria-label="Remarks"
            className="border-b border-status-orange/30 bg-status-orange/10 px-4 py-2 text-xs text-text-primary sm:px-6"
          >
            {notes.length > 0 && (
              <ul className="space-y-0.5">
                {notes.map((n) => (
                  <li key={n.text} title={n.detail ?? undefined}>
                    {n.text}
                  </li>
                ))}
              </ul>
            )}
            {failure && <FailureNote failure={failure} className="mt-1" />}
          </section>
        )}
        <div className="mx-auto max-w-[88rem] break-words px-4 py-5 sm:px-6" data-testid="analysis-content">
          {pollBanner && !loading && (
            <div role="alert" className="mb-4 p-2.5 text-xs text-status-orange bg-status-orange/10 border border-status-orange/20 rounded">
              {pollBanner}
            </div>
          )}
          {reportError && (
            <div role="alert" className="mb-4 p-2.5 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded">
              {reportError}
            </div>
          )}
          {enrichmentToast && (
            <div className="mb-4 p-2.5 text-xs text-status-blue bg-status-blue/10 border border-status-blue/20 rounded">
              {enrichmentToast}
            </div>
          )}
          {children}
        </div>
      </div>
      <Drawer open={subject !== null} title={subject?.title ?? ""} onClose={closeEvidence} returnFocusTo={opener}>
        {subject && <EvidenceDetail jobId={id} subject={subject} />}
      </Drawer>
    </AnalysisContext.Provider>
  );
}
