"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useId, useMemo, useRef, useState, useSyncExternalStore } from "react";
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
import AnalysisHeader, { ChatButton, CompactVerdict, headerFacts } from "./AnalysisHeader";
import ChatDrawer from "./ChatDrawer";
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

/* Wide enough for the chat drawer to sit beside the page instead of over it. */
const DOCKED = "(min-width: 1280px)";

function subscribeDocked(onChange: () => void): () => void {
  if (typeof window.matchMedia !== "function") return () => {};
  const media = window.matchMedia(DOCKED);
  media.addEventListener("change", onChange);
  return () => media.removeEventListener("change", onChange);
}

function useDocked(): boolean {
  return useSyncExternalStore(
    subscribeDocked,
    () => typeof window.matchMedia === "function" && window.matchMedia(DOCKED).matches,
    () => false,
  );
}

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
  const [chatOpen, setChatOpen] = useState(false);
  const chatId = useId();
  const docked = useDocked();
  const headerRef = useRef<HTMLDivElement>(null);
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

  /* The sticky bar takes the verdict in short once the header has scrolled
   * out of view under it.
   *
   * The header used to fold itself on a scroll threshold, and its change of
   * height was the page's scroll glitch: folding took ~45 px out of the
   * document at the very scroll position the fold was decided on, so the
   * content jumped under the pointer, and on a tab barely taller than the
   * window the browser clamped the scroll position and the header opened and
   * folded again. Now nothing above the content changes height: the header
   * scrolls away as part of the document, the bar under it keeps one height,
   * and only what the bar shows changes, read off an observer rather than a
   * scroll listener. */
  useEffect(() => {
    const main = document.getElementById("main-content");
    const header = headerRef.current;
    if (!main || !header || typeof IntersectionObserver !== "function") return;
    const observer = new IntersectionObserver(([entry]) => setCompact(!entry.isIntersecting), {
      root: main,
      threshold: 0,
    });
    observer.observe(header);
    return () => observer.disconnect();
  }, []);

  const openChat = useCallback(() => setChatOpen(true), []);
  const closeChat = useCallback(() => setChatOpen(false), []);

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

  const facts = headerFacts(report, job);
  const ctx = useMemo<AnalysisCtx>(
    () => ({ jobId: id, job, report, loading, reportError, showEvidence, openChat: facts.askable ? openChat : null }),
    [id, job, report, loading, reportError, showEvidence, facts.askable, openChat],
  );
  const chatButton = (iconOnly = false) => (
    <ChatButton open={chatOpen} onClick={() => setChatOpen((v) => !v)} controls={chatId} iconOnly={iconOnly} />
  );
  /* Docked, the drawer takes the page's right edge and the page makes room. */
  const besideChat = chatOpen && docked && facts.askable;

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
      {/* `-m-6` undoes the shell's padding so the header and the sticky bar
          span the column and meet the top edge; the content restores it. The
          sticky line is the scroller's padding edge, 24 px down, hence
          `-top-6`. The bar keeps one height whatever it shows, so nothing
          above the content ever changes height while the page scrolls. */}
      <div
        className={`-m-6 min-h-full bg-bg-deep text-text-primary ${besideChat ? "pr-[420px]" : ""}`}
        data-testid="analysis-page"
      >
        <div ref={headerRef} className="bg-bg-surface">
          <AnalysisHeader
            jobId={id}
            job={job}
            report={report}
            loading={loading}
            theme={theme}
            onTheme={setTheme}
            chat={chatButton()}
          />
        </div>
        {!loading && (
          <div className="sticky -top-6 z-30 border-b border-border bg-bg-surface" data-testid="analysis-bar">
            <div className="flex h-11 items-end gap-3 px-4 sm:px-6">
              <div className="min-w-0 flex-1">
                <Tabs tabs={tabs} active={active} label="Analysis sections" />
              </div>
              {compact && (
                <div className="flex shrink-0 items-center gap-3 self-center">
                  <CompactVerdict facts={facts} />
                  {facts.askable && chatButton(true)}
                </div>
              )}
            </div>
          </div>
        )}
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
        <div className="@container break-words px-4 py-5 sm:px-6" data-testid="analysis-content">
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
      {facts.askable && (
        <ChatDrawer id={chatId} jobId={id} mr={mr} open={chatOpen} docked={docked} onClose={closeChat} />
      )}
      <Drawer open={subject !== null} title={subject?.title ?? ""} onClose={closeEvidence} returnFocusTo={opener}>
        {subject && <EvidenceDetail jobId={id} subject={subject} />}
      </Drawer>
    </AnalysisContext.Provider>
  );
}
