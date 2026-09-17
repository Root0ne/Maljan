"use client";

import { useState } from "react";
import Link from "next/link";

import { useReport } from "./layout";
import { api } from "@/lib/api";
import { countLabel, downloadBlob, downloadObject } from "@/lib/report-utils";
import { getErrorMessage } from "@/lib/errors";
import { ENRICH_BUTTON_LABEL, ENRICH_STATUS_MESSAGE } from "@/lib/enrichment";
import { SEVERITY_STYLES } from "@/types/malware-report";
import type { FpWarning, MalwareReport } from "@/types/malware-report";

function countNetworkIOCs(mr: MalwareReport): {
  domains: number;
  ips: number;
  urls: number;
  suspicious: number;
} {
  const n = mr.network;
  // Also count network IOCs recovered from static
  // strings so a hard-coded C2 domain isn't reported as "0 domains".
  const staticIocs = (mr.static?.interesting_strings ?? []).filter(
    (s) => s.kind === "domain" || s.kind === "ip" || s.kind === "url",
  );
  const staticDomains = staticIocs.filter((s) => s.kind === "domain").length;
  const staticIps = staticIocs.filter((s) => s.kind === "ip").length;
  const staticUrls = staticIocs.filter((s) => s.kind === "url").length;
  if (!n) {
    return {
      domains: staticDomains,
      ips: staticIps,
      urls: staticUrls,
      suspicious: 0,
    };
  }
  const susp =
    n.domains.filter((d) => d.is_suspicious).length +
    n.ips.filter((i) => i.is_suspicious).length;
  return {
    domains: n.domains.length + staticDomains,
    ips: n.ips.length + staticIps,
    urls: n.urls.length + staticUrls,
    suspicious: susp,
  };
}

export default function SummaryTab() {
  const { report, job, loading } = useReport();

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  if (!report && (!job || job.status !== "completed")) {
    return (
      <div className="p-4 text-sm text-text-secondary animate-pulse">
        Analysis in progress... Gathering intelligence.
      </div>
    );
  }

  const mr = report?.malware_report ?? null;
  return mr ? <MalwareReportSummary mr={mr} /> : <LegacySummary />;
}

/* ── Legacy summary (pre-Faz5 reports without malware_report payload) ──
 *
 * A report old enough to carry no `malware_report` has a verdict, a category
 * and the analysts' findings, and nothing else. The verdict and the confidence
 * are in the analysis header; each analyst's confidence, its stance and its
 * claims are the agents table and the stream on the Conversation tab. What is
 * left for this page is the one sentence the run never wrote down, and the way
 * to the argument behind it.
 */
function LegacySummary() {
  const { report, job } = useReport();
  const jobId = report?.job_id ?? job?.id ?? "";
  const agentCount = report?.agent_findings?.length ?? 0;

  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex items-center gap-3">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          This analysis
        </h2>
        {jobId && (
          <Link
            href={`/analysis/${jobId}/conversation`}
            className="ml-auto text-[11px] text-accent-strong hover:underline"
          >
            Read the conversation
          </Link>
        )}
      </div>
      <div className="p-4">
        <p className="text-sm text-text-secondary leading-relaxed">
          This report predates the structured report payload, so it carries a
          verdict, a category and each analyst&apos;s findings and nothing more.
          {report?.malware_category
            ? ` The judge called the behaviour ${report.malware_category}.`
            : ""}
          {agentCount > 0
            ? ` ${countLabel(agentCount, "analyst")} took part; what each one concluded is on the Conversation tab.`
            : ""}
        </p>
      </div>
    </div>
  );
}

/* ── MalwareReport summary payload ───────────────────────────────────── */
function MalwareReportSummary({ mr }: { mr: MalwareReport }) {
  const { report, job } = useReport();
  const reportId = report?.id ?? "";
  const jobId = report?.job_id ?? job?.id ?? "";
  // A report whose judge assessed no severity says so. Falling back to
  // "Informational" would print a rating the run never established.
  const sevStyle = mr.severity
    ? (SEVERITY_STYLES[mr.severity.rating] ?? SEVERITY_STYLES.Informational)
    : SEVERITY_STYLES.Informational;
  const net = countNetworkIOCs(mr);
  const ttpCount = mr.ttp_mappings.length;
  const shortHash = mr.identity.hashes.sha256.slice(0, 12);

  // Surface the degraded flag from run_summary. Nothing lowers the confidence
  // for a degraded run — the judge is told why the run is thin and sets its own
  // number — so this banner is the only thing that says the verdict rests on
  // partial signal. The type is narrow enough that no cast is needed.
  const runSummary = report?.run_summary ?? null;
  const isDegraded = Boolean(runSummary?.degraded_mode);
  const degradationReasons = runSummary?.degradation_reasons ?? [];
  const failedAnalysts = runSummary?.failed_analysts ?? [];
  // Surface FP linter findings in a separate amber
  // banner. ``explanation`` is shown as small muted text below each rule.
  const fpWarnings: FpWarning[] = runSummary?.fp_warnings ?? [];
  const hasErrorWarning = fpWarnings.some((w) => w.severity === "error");
  const evidence = runSummary?.evidence ?? null;
  const ungroundedSections = runSummary?.sections_without_evidence ?? 0;

  return (
    <div className="grid grid-cols-2 gap-4">
      <DownloadBar reportId={reportId} mr={mr} shortHash={shortHash} />

      {isDegraded && (
        <div
          role="alert"
          className="col-span-2 flex items-start gap-3 rounded border border-status-orange/40 bg-status-orange/10 p-3 text-sm"
        >
          <span className="font-semibold text-status-orange shrink-0">
            DEGRADED RUN
          </span>
          <div className="text-text-secondary space-y-1">
            <p>
              The pipeline produced only partial signal, so the verdict and
              severity should be treated as preliminary. The confidence shown
              above is the judge&apos;s own, set knowing the reasons below.
            </p>
            {degradationReasons.length > 0 && (
              <ul className="list-disc list-inside text-xs">
                {degradationReasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            )}
            {failedAnalysts.length > 0 && (
              <p className="text-xs">
                Failed analysts:{" "}
                <code className="font-mono">{failedAnalysts.join(", ")}</code>
              </p>
            )}
          </div>
        </div>
      )}

      {/* Post-pipeline FP linter findings. The
          banner is collapsed by default and auto-expanded if any warning
          is ``severity=error``. */}
      {fpWarnings.length > 0 && (
        <details
          open={hasErrorWarning}
          className="col-span-2 rounded border border-status-orange/40 bg-status-orange/10 p-3 text-sm"
        >
          <summary className="flex items-center gap-3 cursor-pointer select-none">
            <span className="font-semibold text-status-orange">
              QA WARNINGS
            </span>
            <span className="text-xs text-text-muted">
              {fpWarnings.length} finding{fpWarnings.length === 1 ? "" : "s"}
              {hasErrorWarning ? " (errors present)" : ""}
            </span>
          </summary>
          <ul className="mt-2 space-y-2 text-text-secondary">
            {fpWarnings.map((w, i) => (
              <li key={i} className="space-y-0.5">
                <p className="text-xs">
                  <code className="font-mono font-semibold">{w.rule}</code>{" "}
                  <span className="uppercase text-text-muted">
                    [{w.severity}]
                  </span>{" "}
                  {w.message}
                </p>
                {w.field && (
                  <p className="text-[11px] font-mono text-text-muted">
                    field: {w.field}
                  </p>
                )}
                {w.explanation && (
                  <p className="text-[11px] text-text-muted">
                    {w.explanation}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </details>
      )}

      {/* Severity card.
          The verdict and the confidence are in the analysis header, where
          every tab can see them; repeating them here made the same two facts
          read twice on the one tab that also carries the argument for them. */}
      <div className="bg-bg-surface border border-border rounded col-span-2">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Severity
          </h2>
        </div>
        <div className="p-4 grid grid-cols-2 gap-4">
          <div>
            <div className="text-[11px] text-text-muted uppercase tracking-wider mb-1">
              Rating
            </div>
            {mr.severity ? (
              <span
                className={`inline-flex items-center gap-2 px-2 py-0.5 rounded text-xs font-medium ${sevStyle.bg} ${sevStyle.border} ${sevStyle.text} border`}
              >
                {mr.severity.rating}
                <span className="font-mono">{mr.severity.overall_score.toFixed(1)}/10</span>
              </span>
            ) : (
              <span className="text-sm text-text-muted">not assessed</span>
            )}
            {/* The rating alone is a number with no argument behind it. The
                judge writes why it chose that rating, and printing the rating
                without it leaves a reader with nothing to disagree with. */}
            {mr.severity?.business_impact && (
              <p className="mt-1 text-[11px] text-text-muted leading-relaxed">
                {mr.severity.business_impact}
              </p>
            )}
            {(mr.severity?.affected_platforms?.length ?? 0) > 0 && (
              <p className="mt-1 text-[11px] text-text-muted">
                Affects: {mr.severity?.affected_platforms.join(", ")}
              </p>
            )}
          </div>
          <div>
            <div className="text-[11px] text-text-muted uppercase tracking-wider mb-1">
              Category
            </div>
            {/* Free text, printed as written. The category is whatever the
                judge called the behaviour; mapping it onto a fixed list would
                be this console overruling the run. A family is a different
                claim and is not a substitute for one. */}
            <div className="text-sm text-text-primary">
              {mr.malware_category || "Uncategorized"}
            </div>
          </div>
        </div>
      </div>

      {/* What the run found, as counts that open the tab that holds them.
          The techniques and the endpoints are tables on ATT&CK and NETWORK;
          listing the first five of each here was the same finding twice, and
          the shorter of the two copies. */}
      {(ttpCount > 0 || net.domains + net.ips + net.urls > 0) && (
        <div className="col-span-2 bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Findings
            </h2>
          </div>
          <div className="p-4 grid grid-cols-5 gap-3 text-center">
            <CountLink
              label="Techniques"
              value={ttpCount}
              href={`/analysis/${jobId}/capabilities`}
            />
            <CountLink label="Domains" value={net.domains} href={`/analysis/${jobId}/network`} />
            <CountLink label="IPs" value={net.ips} href={`/analysis/${jobId}/network`} />
            <CountLink label="URLs" value={net.urls} href={`/analysis/${jobId}/network`} />
            <CountLink
              label="Suspicious"
              value={net.suspicious}
              href={`/analysis/${jobId}/network`}
              accent={net.suspicious > 0 ? "text-status-red" : undefined}
            />
          </div>
        </div>
      )}

      {/* What the report is standing on. Counted at build time from the
          ledger, so it says how much of the report is checkable and how much
          of it is not — a section with neither a ledger entry nor a named
          finding behind it is a defect, and this is where it shows. */}
      {evidence && (
        <div className="col-span-2 bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border flex items-center gap-3">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Evidence
            </h2>
            <Link
              href={`/analysis/${report?.job_id ?? ""}/evidence`}
              className="ml-auto text-[11px] text-accent-strong hover:underline"
            >
              Open the ledger
            </Link>
          </div>
          <div className="p-4 grid grid-cols-5 gap-3 text-center">
            <Stat label="Calls" value={evidence.entries ?? 0} />
            <Stat label="Succeeded" value={evidence.ok ?? 0} accent="text-status-green" />
            <Stat
              label="Failed"
              value={evidence.failed ?? 0}
              accent={(evidence.failed ?? 0) > 0 ? "text-status-red" : undefined}
            />
            <Stat label="Trimmed" value={evidence.trimmed ?? 0} />
            <Stat
              label="Ungrounded sections"
              value={ungroundedSections}
              accent={ungroundedSections > 0 ? "text-status-orange" : undefined}
            />
          </div>
          {ungroundedSections > 0 && (
            <p className="px-4 pb-4 text-[11px] text-text-muted">
              {ungroundedSections} report{" "}
              {ungroundedSections === 1 ? "section names" : "sections name"} neither a ledger
              entry nor the finding it came from, so nothing in the console can resolve it.
            </p>
          )}
        </div>
      )}

      {/* Executive summary — drawn when the run wrote one. A heading over an
          apology is a section that exists to say it has nothing. */}
      {(mr.executive_summary.trim() || mr.capabilities_narrative.length > 0) && (
        <div className="col-span-2 bg-bg-reading border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Executive Summary
            </h2>
          </div>
          <div className="p-4">
            {mr.executive_summary.trim() && (
              <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-wrap">
                {mr.executive_summary}
              </p>
            )}
            {mr.capabilities_narrative.length > 0 && (
              <ul className="mt-3 space-y-2">
                {mr.capabilities_narrative.map((para, i) => (
                  <li key={i} className="text-sm text-text-secondary leading-relaxed">
                    <span className="text-text-muted mr-2">{i + 1}.</span>
                    {para}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}

      {/* How the run was set up and what it spent, in the one place that
          answers it. This is the rollup the retired pipeline panel carried:
          the job's own configuration, and the parts of the run summary no
          other block on this page says. */}
      <RunRecord runSummary={runSummary} config={job?.config ?? null} />
    </div>
  );
}

/** One count, and the tab that holds what it counts. */
function CountLink({
  label,
  value,
  href,
  accent,
}: {
  label: string;
  value: number;
  href: string;
  accent?: string;
}) {
  return (
    <Link href={href} className="block rounded hover:bg-bg-hover">
      <div className={`text-2xl font-mono ${accent ?? "text-text-primary"}`}>{value}</div>
      <div className="text-[11px] text-text-muted uppercase tracking-wider">{label}</div>
    </Link>
  );
}

/** A job-config value as one line: a string as itself, anything else as JSON. */
function configValue(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

/* What the analysis header already says. The team a run was submitted with is
 * the badge beside the title; listing it again here would put one fact on one
 * screen twice. */
const SHOWN_IN_THE_HEADER = new Set(["profile"]);

/**
 * What this run was told to do, and what it spent doing it.
 *
 * Folded shut, because it answers a question a reader asks about one run in
 * twenty — why this one used that sandbox, how many correction turns the
 * producers needed — and never the first question about a report. Only the
 * facts no other block carries: the stages are the header strip, the ledger
 * counts are the Evidence block above, and the degradation reasons are the
 * banner at the top.
 */
function RunRecord({
  runSummary,
  config,
}: {
  runSummary: MalwareReport["run_summary"] | null;
  config: Record<string, unknown> | null;
}) {
  if (!runSummary) return null;
  const triage = runSummary.triage ?? null;
  const validation = runSummary.validation ?? null;
  const retryMode = Object.entries(runSummary.nudge?.retry_mode ?? {});
  const configRows = Object.entries(config ?? {}).filter(
    ([key]) => !SHOWN_IN_THE_HEADER.has(key),
  );

  return (
    <details className="col-span-2 bg-bg-surface border border-border rounded">
      <summary className="px-4 py-3 cursor-pointer select-none text-xs font-medium text-text-primary uppercase tracking-wider">
        Run record
      </summary>
      <div className="px-4 pb-4 grid grid-cols-2 gap-6 text-xs text-text-secondary">
        <div>
          <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
            Configuration
          </h3>
          {configRows.length === 0 ? (
            <p className="text-text-muted">Submitted with the stored settings, unchanged.</p>
          ) : (
            <ul className="space-y-1">
              {configRows.map(([key, value]) => (
                <li key={key} className="font-mono text-[11px]">
                  <span className="text-text-muted">{key}: </span>
                  {configValue(value)}
                </li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
            What the run spent
          </h3>
          <ul className="space-y-1">
            {triage && (
              <li>
                Triage ran {countLabel(triage.entries, "tool call")}
                {triage.failed > 0 ? `, ${triage.failed} of them failed` : ""}.
              </li>
            )}
            <li>
              {validation?.retries
                ? `${countLabel(validation.retries, "correction turn")} were spent on producers that answered in the wrong shape.`
                : "No producer needed a correction turn."}
            </li>
            {(validation?.unresolved ?? []).map((item, i) => (
              <li key={i} className="text-status-orange">
                {item.agent} left {item.code} unfixed: {item.message}
              </li>
            ))}
            {retryMode.map(([agent, mode]) => (
              <li key={agent} className="text-text-muted">
                {agent} needed the final-answer nudge sent as {mode}.
              </li>
            ))}
          </ul>
        </div>
      </div>
    </details>
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: string;
}) {
  return (
    <div>
      <div className={`text-2xl font-mono ${accent ?? "text-text-primary"}`}>{value}</div>
      <div className="text-[11px] text-text-muted uppercase tracking-wider">{label}</div>
    </div>
  );
}

function DownloadBar({
  reportId,
  mr,
  shortHash,
}: {
  reportId: string;
  mr: MalwareReport;
  shortHash: string;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  // A failed markdown fetch
  // left the button looking like it had worked.
  const [error, setError] = useState<string | null>(null);

  const safeName = `maljan-${shortHash}`;

  const downloadMarkdown = async () => {
    if (!reportId) return;
    setBusy("md");
    setError(null);
    try {
      const body = await api.getReportMarkdown(reportId);
      downloadBlob(body, `${safeName}.md`, "text/markdown");
    } catch (err) {
      setError(`Could not download the Markdown report: ${getErrorMessage(err)}`);
    } finally {
      setBusy(null);
    }
  };

  const downloadPdf = async () => {
    if (!reportId) return;
    setBusy("pdf");
    setError(null);
    try {
      // Server-rendered: A4, numbered pages, linked contents and the
      // deterministic figures in place. Can take a second on a figure-heavy
      // report, hence the busy state on the button.
      downloadObject(await api.getReportPdf(reportId), `${safeName}.pdf`);
    } catch (err) {
      setError(`Could not download the PDF report: ${getErrorMessage(err)}`);
    } finally {
      setBusy(null);
    }
  };

  const downloadHtml = async () => {
    if (!reportId) return;
    setBusy("html");
    setError(null);
    try {
      const body = await api.getReportHtml(reportId);
      downloadBlob(body, `${safeName}.html`, "text/html");
    } catch (err) {
      setError(`Could not download the HTML report: ${getErrorMessage(err)}`);
    } finally {
      setBusy(null);
    }
  };

  /* The IOC, ATT&CK and timeline endpoints all worked and nothing in the UI
   * reached any of them — the only way to an IOC
   * list was to read the markdown report or call the API by hand. Each fetches
   * its own endpoint and saves the answer; a failure says so in the same
   * banner the document exports use. */
  const downloadJson = (kind: "iocs" | "mitre" | "timeline") => async () => {
    if (!reportId) return;
    setBusy(kind);
    setError(null);
    try {
      const body =
        kind === "iocs"
          ? await api.getReportIOCs(reportId)
          : kind === "mitre"
            ? await api.getReportMitre(reportId)
            : await api.getReportTimeline(reportId);
      downloadBlob(JSON.stringify(body, null, 2), `${safeName}-${kind}.json`, "application/json");
    } catch (err) {
      setError(`Could not download the ${kind} export: ${getErrorMessage(err)}`);
    } finally {
      setBusy(null);
    }
  };

  const downloadMisp = () => {
    const body = JSON.stringify(mr.misp_attributes ?? [], null, 2);
    downloadBlob(body, `${safeName}-misp.json`, "application/json");
  };

  const mispDisabled = !mr.misp_attributes || mr.misp_attributes.length === 0;

  return (
    <div className="col-span-2 flex flex-wrap items-center gap-2">
      <span className="text-[11px] text-text-muted uppercase tracking-wider mr-1">
        Export
      </span>
      <button
        onClick={downloadMarkdown}
        disabled={!reportId || busy === "md"}
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed"
      >
        {busy === "md" ? "fetching..." : "↓ Markdown report"}
      </button>
      <button
        onClick={downloadPdf}
        disabled={!reportId || busy === "pdf"}
        title="Print-ready A4 report with figures and a linked table of contents"
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed"
      >
        {busy === "pdf" ? "rendering..." : "↓ PDF report"}
      </button>
      <button
        onClick={downloadHtml}
        disabled={!reportId || busy === "html"}
        title="Self-contained HTML — opens offline, no external requests"
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed"
      >
        {busy === "html" ? "fetching..." : "↓ HTML report"}
      </button>
      <button
        onClick={downloadJson("iocs")}
        disabled={!reportId || busy === "iocs"}
        title="Every indicator the report holds, as JSON"
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed"
      >
        {busy === "iocs" ? "fetching..." : "\u2193 IOC list"}
      </button>
      <button
        onClick={downloadJson("mitre")}
        disabled={!reportId || busy === "mitre"}
        title="The ATT&CK techniques this report mapped, as JSON"
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed"
      >
        {busy === "mitre" ? "fetching..." : "\u2193 MITRE ATT&CK"}
      </button>
      <button
        onClick={downloadJson("timeline")}
        disabled={!reportId || busy === "timeline"}
        title="The negotiation timeline, round by round, as JSON"
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed"
      >
        {busy === "timeline" ? "fetching..." : "\u2193 Timeline"}
      </button>
      <button
        onClick={downloadMisp}
        disabled={mispDisabled}
        title={mispDisabled ? "No MISP attributes generated for this report" : undefined}
        className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed"
      >
        ↓ MISP attributes
      </button>
      <EnrichButton reportId={reportId} />
      {error && (
        <div
          role="alert"
          className="w-full text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
        >
          {error}
        </div>
      )}
    </div>
  );
}

/**
 * The one button that asks the threat-intel services about this report.
 *
 * It used to sit on NETWORK and on ATTRIBUTION, two copies of one action
 * against one endpoint, so a reader who pressed both queued nothing twice and
 * learned that from a message on only one of the two tabs. It belongs on the
 * tab a reader lands on, beside the exports, because what it changes — the
 * reputation of the endpoints, the nearest-neighbour cases — is spread across
 * the tabs it used to live on.
 */
function EnrichButton({ reportId }: { reportId: string }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const run = async () => {
    if (!reportId || busy) return;
    setBusy(true);
    setMessage(null);
    try {
      // The endpoint distinguishes queued / already_queued /
      // skipped_no_network_iocs — say which one happened rather than always
      // promising a refresh.
      const res = await api.enrichReport(reportId);
      setMessage(ENRICH_STATUS_MESSAGE[res.status] ?? ENRICH_STATUS_MESSAGE.queued);
    } catch (err) {
      setMessage(`Could not queue enrichment: ${getErrorMessage(err)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button
        onClick={run}
        disabled={!reportId || busy}
        className="ml-auto px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed"
      >
        {busy ? "queueing..." : ENRICH_BUTTON_LABEL}
      </button>
      {message && (
        <p className="w-full text-xs text-text-secondary bg-bg-active border border-border rounded px-2 py-1.5">
          {message}
        </p>
      )}
    </>
  );
}
