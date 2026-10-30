"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ChevronRight } from "lucide-react";
import CopyButton from "@/components/ui/CopyButton";
import KpiTile from "@/components/ui/KpiTile";
import Section from "@/components/ui/Section";
import { SeverityPill } from "@/components/ui/Pill";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { countLabel } from "@/lib/report-utils";
import { useRun } from "@/lib/useRun";
import { PRIORITY_STYLES, type DefensiveCategory, type FollowUp, type MalwareReport } from "@/types/malware-report";
import { useReport } from "./AnalysisContext";
import CitedProse from "./CitedProse";
import EvidenceChips from "./EvidenceChips";
import { FollowUpList } from "./FollowUpQuestions";
import PipelineStrip from "./PipelineStrip";
import ReportAbsent from "./ReportAbsent";
import { ScrollToAnchor } from "./ReportGate";
import { reportAbsence } from "./reportAbsence";
import { FOLLOW_UP_EVENT, canAskFollowUp, followUpRows } from "./followUps";
import { keyFindings, noSummaryReason, outcomeLine, questionAnswers } from "./reportProse";
import {
  VOICE_TEXT,
  analysisHref,
  configText,
  findingRows,
  howObtained,
  kpis,
  proseText,
  sortedRecommendations,
  type FindingRow,
} from "./overview";

/**
 * Overview: the page a reader lands on, and the same content as the first
 * pages of the report.
 *
 * Top to bottom: what the sample does (the summary and its key findings),
 * how much of each kind of evidence exists (the number row, with "Not found"
 * where none does), the answers to the questions the analysis was asked, the
 * findings table highest severity first with a caret that opens the evidence
 * behind a row, the configuration the analysis extracted, what to do about
 * it, and the questions asked after it finished.
 */

const FIRST_ROWS = 10;
const FIRST_KEY_FINDINGS = 8;

const CATEGORY_LABELS: Record<DefensiveCategory, string> = {
  firewall: "Firewall / Network",
  edr_hunting: "EDR Hunting",
  registry_hardening: "Registry Hardening",
  gpo: "Group Policy",
  patching: "Patching",
  user_awareness: "User Awareness",
  other: "Other",
};

export default function OverviewTab() {
  const { jobId, report, job, loading, reportError, showEvidence } = useReport();
  const [allRows, setAllRows] = useState(false);
  const [allFindings, setAllFindings] = useState(false);

  if (loading) return <p className="text-sm text-text-muted">Loading the analysis…</p>;
  const absent = reportAbsence({ report, job, reportError });
  if (absent) {
    return absent.kind === "running" ? <RunningOverview jobId={jobId} text={absent.text} /> : <ReportAbsent absence={absent} />;
  }
  const mr = report?.malware_report ?? null;
  if (!report || !mr) return <LegacyOverview />;

  const findings = keyFindings(mr);
  const shownFindings = allFindings ? findings : findings.slice(0, FIRST_KEY_FINDINGS);
  const storedParagraphs = mr.capabilities_narrative ?? [];
  const summaryAbsentBecause = noSummaryReason(mr);
  const rows = findingRows(mr);
  const visible = allRows ? rows : rows.slice(0, FIRST_ROWS);
  const config = mr.technical_analysis?.configuration ?? [];
  const recs = sortedRecommendations(mr.defensive_recommendations);

  const openRow = (row: FindingRow, opener: HTMLElement) =>
    showEvidence?.(
      {
        title: row.title,
        severity: row.severity,
        category: row.category,
        voice: row.voice,
        details: row.details,
        techniques: row.techniques,
        evidenceIds: row.evidenceIds,
      },
      opener,
    );

  return (
    <div className="space-y-5">
      <Section
        title="Summary"
        empty={!mr.executive_summary?.trim() && findings.length === 0 && storedParagraphs.length === 0 && !summaryAbsentBecause}
      >
        <div className="max-w-[72ch] space-y-3">
          {mr.severity && (
            <p className="flex flex-wrap items-center gap-2 text-sm text-text-secondary">
              <SeverityPill severity={mr.severity.rating} />
              {mr.severity.business_impact && (
                <span>
                  <CitedProse text={mr.severity.business_impact} />
                </span>
              )}
            </p>
          )}
          {mr.executive_summary?.trim() && (
            <p className="whitespace-pre-wrap text-sm leading-6 text-text-primary">
              <CitedProse text={mr.executive_summary} />
            </p>
          )}
          {!mr.executive_summary?.trim() && findings.length === 0 && summaryAbsentBecause && (
            <p className="text-sm text-text-muted">No summary was written: {summaryAbsentBecause}.</p>
          )}
          {shownFindings.length > 0 && (
            <ul className="list-disc space-y-1 pl-5 text-sm leading-6 text-text-primary" aria-label="Key findings">
              {shownFindings.map((f, i) => (
                <li key={`${i}-${f.text}`}>
                  <CitedProse text={f.text} />
                  {f.evidence_ids.length > 0 && (
                    <sup className="ml-0.5">
                      <button
                        type="button"
                        onClick={(e) =>
                          showEvidence?.(
                            { title: proseText(f.text), details: [], techniques: [], evidenceIds: f.evidence_ids },
                            e.currentTarget,
                          )
                        }
                        aria-label={`Evidence for key finding ${i + 1}`}
                        className="inline-flex h-4 min-w-4 items-center justify-center rounded px-0.5 text-[10px] font-medium leading-none text-accent-strong hover:underline"
                      >
                        {i + 1}
                      </button>
                    </sup>
                  )}
                </li>
              ))}
            </ul>
          )}
          {findings.length > FIRST_KEY_FINDINGS && (
            <button
              type="button"
              onClick={() => setAllFindings((v) => !v)}
              className="text-xs text-accent-strong hover:underline"
            >
              {allFindings
                ? `Show the first ${FIRST_KEY_FINDINGS}`
                : `Show ${findings.length - FIRST_KEY_FINDINGS} more key findings`}
            </button>
          )}
          {storedParagraphs.length > 0 && (
            <ol className="list-decimal space-y-2 pl-5 text-sm leading-6 text-text-secondary">
              {storedParagraphs.map((para, i) => (
                <li key={i}>
                  <CitedProse text={para} />
                </li>
              ))}
            </ol>
          )}
        </div>
      </Section>

      {/* Numbers, not links: the tab each one counts is named in the tab row
          right above, and the first screen keeps to ten controls. */}
      <section aria-label="Counts">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
          {kpis(mr).map((k) => (
            <KpiTile key={k.key} label={k.label} value={k.value} />
          ))}
        </div>
      </section>

      <QuestionAnswers mr={mr} />

      <Section title="Top findings" count={rows.length} empty={rows.length === 0}>
        <div className="-mx-4 -my-3 overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border-light text-left text-xs text-text-muted">
                <th scope="col" className="px-4 py-2 font-medium">Severity</th>
                <th scope="col" className="hidden px-2 py-2 font-medium sm:table-cell">Category</th>
                <th scope="col" className="px-2 py-2 font-medium">Finding</th>
                <th scope="col" className="hidden px-2 py-2 font-medium md:table-cell">How it is known</th>
                <th scope="col" className="w-10 px-2 py-2">
                  <span className="sr-only">Evidence</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {visible.map((row) => (
                <tr key={row.id} className="border-b border-border-light last:border-b-0 hover:bg-bg-hover">
                  <td className="whitespace-nowrap px-4 py-2 align-top">
                    <SeverityPill severity={row.severity} />
                  </td>
                  <td className="hidden px-2 py-2 align-top text-text-secondary sm:table-cell">{row.category}</td>
                  <td className="px-2 py-2 align-top text-text-primary">
                    {row.title}
                    {row.techniques.length > 0 && (
                      <span className="ml-1.5 font-mono text-[11px] text-text-muted">{row.techniques.join(", ")}</span>
                    )}
                  </td>
                  <td className="hidden px-2 py-2 align-top text-xs text-text-secondary md:table-cell">
                    {VOICE_TEXT[row.voice]}
                  </td>
                  <td className="px-2 py-1.5 align-top">
                    <button
                      type="button"
                      onClick={(e) => openRow(row, e.currentTarget)}
                      aria-label={`Show evidence: ${row.title}`}
                      className="inline-flex h-7 w-7 items-center justify-center rounded text-text-secondary hover:bg-bg-active hover:text-text-primary"
                    >
                      <ChevronRight aria-hidden="true" className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length > FIRST_ROWS && (
            <div className="border-t border-border-light px-4 py-2 text-xs">
              <button type="button" onClick={() => setAllRows((v) => !v)} className="text-accent-strong hover:underline">
                {allRows ? "Show the first 10" : `Show ${rows.length - FIRST_ROWS} more`}
              </button>
            </div>
          )}
        </div>
      </Section>

      <div className="grid gap-5 lg:grid-cols-2">
        <Section
          title="Extracted configuration"
          count={config.length}
          empty={config.length === 0}
          actions={<CopyButton value={configText(config)} what="the whole configuration" label="copy all" />}
        >
          <dl className="space-y-2 text-sm">
            {config.map((item) => (
              <div key={`${item.key}=${item.value}`} className="grid grid-cols-[minmax(6rem,10rem)_1fr_auto] items-start gap-2">
                <dt className="text-text-secondary">{item.key}</dt>
                <dd className="min-w-0">
                  <span className="break-all font-mono text-xs text-text-primary">{item.value}</span>
                  <span className="block text-[11px] text-text-muted">{howObtained(item)}</span>
                </dd>
                <CopyButton value={item.value} what={`configuration value ${item.key}`} label="copy" />
              </div>
            ))}
          </dl>
        </Section>

        <div id="recommendations" className="scroll-mt-40">
          <Section title="Recommendations" count={recs.length} empty={recs.length === 0}>
            <ol className="space-y-3 text-sm">
              {recs.map((r) => {
                const p = PRIORITY_STYLES[r.priority];
                return (
                  <li key={`${r.priority}-${r.action}`} className="flex gap-3">
                    <span
                      className={`mt-0.5 inline-flex h-5 shrink-0 items-center rounded px-1.5 text-[11px] font-semibold ${p?.text ?? "text-text-secondary"} ${p?.bg ?? "bg-bg-active"}`}
                      title={p?.label}
                    >
                      {r.priority}
                    </span>
                    <div className="min-w-0">
                      <p className="text-text-primary">
                        <CitedProse text={r.action} />
                      </p>
                      <p className="mt-0.5 flex flex-wrap items-center gap-2 text-[11px] text-text-muted">
                        <span>{CATEGORY_LABELS[r.category] ?? r.category}</span>
                        {r.technique_id && (
                          <a
                            href={`https://attack.mitre.org/techniques/${r.technique_id.split(".").map(encodeURIComponent).join("/")}/`}
                            target="_blank"
                            rel="noreferrer"
                            className="font-mono text-status-purple hover:underline"
                            title="ATT&CK technique this recommendation defends against"
                          >
                            {r.technique_id}
                          </a>
                        )}
                      </p>
                      {r.rationale && (
                        <p className="mt-0.5 text-xs text-text-secondary">
                          <CitedProse text={r.rationale} />
                        </p>
                      )}
                      {r.detection && <p className="mt-0.5 text-xs text-text-muted">Detect with: {r.detection}</p>}
                    </div>
                  </li>
                );
              })}
            </ol>
          </Section>
        </div>
      </div>

      <FollowUps jobId={jobId} status={job?.status} />
      <ScrollToAnchor />
    </div>
  );
}

/** While the job runs: how far it has got, and the way to the live discussion. */
function RunningOverview({ jobId, text }: { jobId: string; text: string }) {
  const run = useRun(jobId || null);
  return (
    <div className="space-y-4">
      <p role="status" className="text-sm text-text-secondary">
        {text}
      </p>
      <PipelineStrip stages={run.stages} roster={run.roster} />
      <Link href={`${analysisHref(jobId, "evidence")}/conversation`} className="inline-block text-sm text-accent-strong hover:underline">
        Follow the analysts&apos; discussion live
      </Link>
    </div>
  );
}

/* A report old enough to carry no structured payload has a verdict, a
 * category and the analysts' findings, and nothing else. The verdict is in
 * the header; what each analyst concluded is under Evidence, beside their
 * discussion. */
function LegacyOverview() {
  const { report, jobId } = useReport();
  const agentCount = report?.agent_findings?.length ?? 0;
  return (
    <Section title="This analysis">
      <p className="max-w-[72ch] text-sm leading-relaxed text-text-secondary">
        This report predates the structured report payload, so it carries a verdict, a category and each
        analyst&apos;s findings and nothing more.
        {report?.malware_category ? ` The analysis called the behaviour ${report.malware_category}.` : ""}
        {agentCount > 0 ? ` ${countLabel(agentCount, "analyst")} took part; what each one concluded is ` : ""}
        {agentCount > 0 && (
          <>
            <Link href={`${analysisHref(jobId, "evidence")}/conversation`} className="text-accent-strong hover:underline">
              beside their discussion
            </Link>
            .
          </>
        )}
      </p>
    </Section>
  );
}

/* Each question the analysis was asked when it was submitted, the outcome the
 * report stands by and its answer. The exported report leads with the same
 * section. Nothing is drawn for an analysis asked nothing. */
function QuestionAnswers({ mr }: { mr: MalwareReport }) {
  const answers = questionAnswers(mr);
  if (answers.length === 0) return null;
  return (
    <Section title="Your questions" count={answers.length}>
      <ol className="max-w-[72ch] space-y-4">
        {answers.map((answer, i) => (
          <li key={i} className="space-y-1.5">
            <p className="text-sm font-medium text-text-primary">
              Q{i + 1}. {answer.question}
            </p>
            <p className="text-xs">
              <span className="mr-2 text-text-muted">Outcome</span>
              <span className={answer.answered ? "text-status-orange" : "text-text-secondary"}>
                {outcomeLine(answer)}
              </span>
            </p>
            {answer.answer.trim() && (
              <p className="text-sm leading-relaxed text-text-secondary">
                <CitedProse text={answer.answer} />
                <EvidenceChips ids={answer.evidence_ids} />
              </p>
            )}
            {answer.looked_at.length > 0 && (
              <p className="text-xs text-text-muted">
                Also looked at <EvidenceChips ids={answer.looked_at} />
              </p>
            )}
            {answer.open_questions.length > 0 && (
              <p className="text-xs text-text-muted">Open questions it rests on: {answer.open_questions.join("; ")}</p>
            )}
            {answer.checks.map((check, j) => (
              <p key={j} className="text-[11px] italic text-text-muted">
                Check: {check}
              </p>
            ))}
          </li>
        ))}
      </ol>
    </Section>
  );
}

/* The questions asked after the analysis finished (the header's Ask), with
 * every answer. Drawn only once one has been asked; a new answer from the
 * header joins the list without a reload. */
function FollowUps({ jobId, status }: { jobId: string; status: string | null | undefined }) {
  const [rows, setRows] = useState<FollowUp[]>([]);
  const [error, setError] = useState<string | null>(null);
  const open = canAskFollowUp(status);

  useEffect(() => {
    if (!jobId || !open) return;
    let live = true;
    api
      .getFollowUps(jobId)
      .then((res) => {
        if (live) setRows(followUpRows(res.follow_ups));
      })
      .catch((err) => {
        if (live) setError(`Could not read the follow-up questions: ${getErrorMessage(err)}`);
      });
    const onAnswer = (e: Event) => {
      const row = (e as CustomEvent<FollowUp>).detail;
      if (row) setRows((held) => followUpRows([...held, row]));
    };
    window.addEventListener(FOLLOW_UP_EVENT, onAnswer);
    return () => {
      live = false;
      window.removeEventListener(FOLLOW_UP_EVENT, onAnswer);
    };
  }, [jobId, open]);

  if (!open || (rows.length === 0 && !error)) return null;
  return (
    <Section title="Follow-up questions" count={rows.length}>
      <div className="max-w-[72ch] space-y-3">
        <p className="text-[11px] text-text-muted">Answered from what this analysis stored; nothing is analysed again.</p>
        {error ? <p className="text-xs text-status-red">{error}</p> : <FollowUpList rows={rows} jobId={jobId} />}
      </div>
    </Section>
  );
}
