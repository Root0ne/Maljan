"use client";

import Link from "next/link";
import { usePathname, useParams } from "next/navigation";
import { useEffect, useMemo, useRef, useState, createContext, useContext } from "react";
import {
  Activity,
  Anchor,
  Binary,
  CircleAlert,
  CircleCheck,
  CircleHelp,
  CircleMinus,
  FileText,
  Globe,
  IdCard,
  LayoutGrid,
  MessagesSquare,
  ScrollText,
  Shield,
  ShieldCheck,
  Tags,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { api } from "@/lib/api";
import type { ReportDetailDTO, JobDTO } from "@/lib/api";
import PipelineStrip from "@/components/analysis/PipelineStrip";
import FailureNote from "@/components/ui/FailureNote";
import { TAB_GROUP_ORDER, tabsFor, type TabIcon } from "@/components/analysis/analysisTabs";
import {
  hydrateRunTranscript,
  setRunRoster,
  setRunStoredStages,
} from "@/lib/runStore";
import { useRun } from "@/lib/useRun";
import { formatDateTime, formatDuration } from "@/lib/report-utils";
import { verdictBucket } from "@/lib/verdict";
import {
  assessedSeverity,
  verdictHeadline,
  verdictReadingNote,
  VERDICT_CONFLICT_NOTE,
} from "@/lib/verdictHeader";
import { getErrorMessage, isApiStatus } from "@/lib/errors";
import { jobFailure } from "@/lib/runFailure";
import type { VerdictBucket } from "@/lib/verdict";

/* ── Report Context (shared with child tabs) ─────────── */
interface ReportCtx {
  report: ReportDetailDTO | null;
  job: JobDTO | null;
  loading: boolean;
}

/* The run's events are deliberately absent here. They live in the run store,
 * keyed by job id, where they survive a route change and a second reader —
 * a tab that needs them subscribes with `useRun` rather than being handed a
 * copy that dies with this layout. */
const ReportContext = createContext<ReportCtx>({
  report: null,
  job: null,
  loading: true,
});
export function useReport() {
  return useContext(ReportContext);
}

/* ── Verdict badge config ──────────────────────────────
 * Keyed by the shared `VerdictBucket` rather than a
 * hand-rolled lower-cased raw verdict, so the backend's "Malware" spelling
 * can never miss the map and fall through to the muted "unknown" styling.
 * The human label comes from `verdictLabel` for the same reason. */
const VERDICT_CONFIG: Record<
  VerdictBucket,
  { border: string; text: string; icon: LucideIcon }
> = {
  malicious: {
    border: "border-status-red/40",
    text: "text-status-red",
    icon: CircleAlert,
  },
  suspicious: {
    border: "border-status-orange/40",
    text: "text-status-orange",
    icon: CircleHelp,
  },
  benign: {
    border: "border-status-green/40",
    text: "text-status-green",
    icon: CircleCheck,
  },
  unknown: {
    border: "border-text-muted/40",
    text: "text-text-muted",
    icon: CircleMinus,
  },
};

/** The icon each tab is drawn with, keyed by the name `analysisTabs` gives it. */
const TAB_ICON: Record<TabIcon, LucideIcon> = {
  summary: FileText,
  conversation: MessagesSquare,
  identity: IdCard,
  static: Binary,
  dynamic: Activity,
  network: Globe,
  persistence: Anchor,
  attack: LayoutGrid,
  attribution: Tags,
  detection: ShieldCheck,
  defense: Shield,
  evidence: ScrollText,
};

export default function AnalysisLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const params = useParams();
  const pathname = usePathname();
  const id = params.id as string;
  const basePath = `/analysis/${id}`;

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
  const [enrichmentToast, setEnrichmentToast] = useState<string | null>(null);
  const refetchRef = useRef<(() => Promise<void>) | null>(null);

  useEffect(() => {
    let cancelled = false;
    const TERMINAL = new Set(["completed", "failed"]);
    const POLL_INTERVAL = 3000;

    async function refetchReport(terminal = false) {
      if (cancelled) return;
      try {
        const r = await api.getReportByJobId(id);
        if (cancelled) return;
        setReport(r);
        setReportError(null);
      } catch (err) {
        // While the job is
        // still running a missing report is expected, so stay quiet. Once the
        // job is terminal the report should exist — surface the failure.
        if (!cancelled && terminal) {
          setReportError(
            getErrorMessage(err) || "Could not load the report for this job.",
          );
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

        if (TERMINAL.has(j.status)) {
          await refetchReport(true);
          if (!cancelled) setLoading(false);
          return; // stop polling
        }

        // Job still running — schedule next poll
        if (!cancelled) setLoading(false);
        setTimeout(() => { if (!cancelled) fetchAll(); }, POLL_INTERVAL);
      } catch (err) {
        // Report *why* the API call failed instead of only
        // the generic "could not connect" banner.
        if (!cancelled) {
          if (isApiStatus(err, 404)) setNotFound(true);
          else setApiError(getErrorMessage(err) || "Unknown error");
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

  /* What the layout itself needs from the feed: a report to refetch when
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
   * the API's is ever consulted. The client's clock used to be the other half
   * of it, and a dev box a few seconds ahead of the API could swallow a live
   * toast.
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

  /* Derive header data strictly from real API data — no mock fallback */
  const verdict = verdictBucket(report?.verdict);
  const headline = verdictHeadline(
    report?.verdict,
    report?.overall_confidence,
    assessedSeverity(report?.malware_report),
  );
  const readingNote = verdictReadingNote(report?.verdict_reading);
  const category = report?.malware_category ?? "";
  // Prefer a readable sample identity (filename, then hash prefix) over
  // the opaque sample_id UUID — available from the job even during the live run,
  // before the rich report's identity payload lands.
  const jobSampleLabel =
    job?.sample_filename ||
    (job?.sample_sha256 ? `${job.sample_sha256.slice(0, 16)}…` : "");
  const duration = formatDuration(job?.duration_seconds);
  // Use the one canonical timestamp format instead of
  // the locale default, which rendered as "26.07.2026 11:04:51" here while the
  // sample/report lists showed "Jul 5, 2026, 07:34 PM".
  const analyzedAtIso = report?.created_at ?? job?.created_at;
  const analyzedAt = analyzedAtIso ? formatDateTime(analyzedAtIso) : "";

  const v = VERDICT_CONFIG[verdict];
  const VerdictIcon = v.icon;

  /* What a failed run says about itself. The status chip said that it failed
   * and nothing said why: the worker's own sentence, and the id the log
   * entries holding the traceback are filed under, were on the job all along.
   * A row carrying neither, and a run that ended any other way, are left to
   * the chip. */
  const failure = jobFailure(job?.status, job?.error_message);

  /* The tabs this run earned. A tab is a promise that there is something
   * behind it, so one the run never filled is absent rather than present and
   * apologetic — and while the job is still running only the three that can
   * answer anything are offered. */
  const tabs = useMemo(() => tabsFor(report), [report]);

  /* The H1 should identify the sample, not restate the verdict (the verdict
   * badge already shows it). Prefer the original filename from the rich
   * MalwareReport identity payload; fall back to a hash prefix if neither
   * the report nor the legacy fields have it. */
  const identity = report?.malware_report?.identity;
  const fileName = identity?.file_name?.trim();
  const sha256 = identity?.hashes?.sha256;
  const headerTitle =
    fileName || (sha256 ? `${sha256.slice(0, 16)}…` : "") || jobSampleLabel || "Pending analysis";
  const family = report?.malware_report?.attribution?.family;
  const headerSubtitle = family || category || "";

  /* Nothing on this page said which analyst
   * line-up produced the report, so a `lean` run — network only — read as a
   * full one, the deterministic static layers being present either way. A
   * report written before profiles existed has no such key and shows nothing,
   * and neither does the default line-up, which is what "no badge" has always
   * meant. */
  const profile = (report?.run_summary as {
    profile?: { name?: string; analysts?: string[] } | null;
  } | null)?.profile;
  const profileName = profile?.name;
  const profileBadge = profileName && profileName !== "default" ? profileName : null;
  const profileAnalysts = profile?.analysts ?? [];

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
    <ReportContext.Provider value={{ report, job, loading }}>
      <div>
        {!apiAvailable && !loading && (
          <div role="alert" className="mb-4 p-2.5 text-xs text-status-orange bg-status-orange/10 border border-status-orange/20 rounded">
            Could not connect to the API. Please ensure the backend is running.
            {apiError ? ` (${apiError})` : ""}
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

        {/* Header */}
        <div className="bg-bg-surface border border-border rounded p-4 mb-4">
          <div className="flex items-start gap-5">
            {/* Verdict Badge */}
            <div
              className={`flex items-center justify-center w-10 h-10 rounded-full border ${v.border} ${v.text} shrink-0`}
            >
              <VerdictIcon size={18} aria-hidden="true" />
            </div>

            {/* Info */}
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 mb-1">
                <h1 className="text-lg font-semibold text-text-primary truncate max-w-full" title={headerTitle}>
                  {headerTitle}
                </h1>
                <span
                  className={`text-xs px-2 py-0.5 rounded ${
                    headline.conflict
                      ? "border border-status-orange/40 bg-status-orange/10 text-status-orange"
                      : `bg-bg-active ${v.text}`
                  }`}
                >
                  {headline.text}
                </span>
                {headerSubtitle && (
                  <span className="text-xs text-text-secondary bg-bg-active px-2 py-0.5 rounded">
                    {headerSubtitle}
                  </span>
                )}
                {profileBadge && (
                  <span
                    className="text-xs text-accent-strong bg-accent/10 px-2 py-0.5 rounded"
                    title={
                      profileAnalysts.length > 0
                        ? `Analysts: ${profileAnalysts.join(", ")}`
                        : undefined
                    }
                  >
                    Profile: {profileBadge}
                  </span>
                )}
                {job && (
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    job.status === "completed" ? "text-status-green bg-status-green/10" :
                    job.status === "running" ? "text-status-blue bg-status-blue/10" :
                    job.status === "failed" ? "text-status-red bg-status-red/10" :
                    "text-text-muted bg-bg-active"
                  }`}>
                    {job.status.toUpperCase()}
                  </span>
                )}
              </div>

              {headline.conflict && (
                <p className="mb-1 text-xs text-status-orange">{VERDICT_CONFLICT_NOTE}</p>
              )}

              {/* Three of the four readings publish one of the same three
                  words a judge may state, so the verdict above cannot be read
                  on its own. The markdown report has said which since the
                  reading existed; this is that sentence, here. */}
              {readingNote && (
                <p className="mb-1 text-xs text-status-orange">{readingNote}</p>
              )}

              {failure && <FailureNote failure={failure} className="mb-1.5" />}

              {/* The sample is the `h1` above. A "Sample:" line under it was
                  the same filename a second time, and for a hash-named sample
                  the same hash. */}
              <div className="flex flex-wrap gap-x-6 gap-y-1 text-xs text-text-secondary">
                <div>
                  <span className="text-text-muted">Duration: </span>
                  {duration}
                </div>
                <div>
                  <span className="text-text-muted">Analyzed: </span>
                  {analyzedAt}
                </div>
              </div>

              {/* The shape of the run, in the one place every tab can see it. */}
              <PipelineStrip stages={run.stages} roster={run.roster} />
            </div>
          </div>
        </div>

        {/* Tab Bar — grouped by section with thin separators */}
        <nav aria-label="Analysis sections" className="flex flex-wrap items-end border-b border-border mb-4">
          {TAB_GROUP_ORDER.map((group, gi) => {
            const groupTabs = tabs.filter((t) => t.group === group);
            if (groupTabs.length === 0) return null;
            // A separator belongs between two groups that both drew something,
            // never before the first one a run happens to have.
            const earlier = TAB_GROUP_ORDER.slice(0, gi).some((g) =>
              tabs.some((t) => t.group === g),
            );
            return (
              <div key={group} className="flex items-end">
                {earlier && (
                  <span
                    aria-hidden="true"
                    className="h-5 w-px bg-border mx-1.5 mb-2 self-center"
                  />
                )}
                {groupTabs.map((tab) => {
                  const href = `${basePath}${tab.key}`;
                  const active =
                    tab.key === ""
                      ? pathname === basePath
                      : pathname.startsWith(href);
                  const Icon = TAB_ICON[tab.icon];
                  return (
                    <Link
                      key={tab.key}
                      href={href}
                      aria-current={active ? "page" : undefined}
                      className={`flex items-center gap-1.5 px-3 py-2.5 text-xs font-medium uppercase tracking-wider border-b-2 ${
                        active
                          ? "border-accent text-accent"
                          : "border-transparent text-text-secondary hover:text-text-primary"
                      }`}
                    >
                      <Icon size={16} aria-hidden="true" />
                      {tab.label}
                    </Link>
                  );
                })}
              </div>
            );
          })}
        </nav>

        {/* Tab Content */}
        {children}
      </div>
    </ReportContext.Provider>
  );
}
