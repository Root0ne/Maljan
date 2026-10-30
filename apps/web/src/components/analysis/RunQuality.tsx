"use client";

import { useRun } from "@/lib/useRun";
import { rosterNames } from "@/lib/rosterNames";
import {
  bundleLossSentence,
  corpusHeldSentence,
  serverRestSentence,
  tokensSentence,
  countLabel,
  formatDuration,
  partialGroundingSentence,
} from "@/lib/report-utils";
import { enrichmentAskSentence, enrichmentAsks } from "@/lib/enrichment";
import { degradedBannerText } from "@/lib/degradedBanner";
import { validationRowClass, validationRowText } from "@/lib/validationRows";
import {
  assessedSeverity,
  verdictHeadline,
  verdictReadingNote,
  VERDICT_CONFLICT_NOTE,
} from "@/lib/verdictHeader";
import Section from "@/components/ui/Section";
import { useReport } from "@/components/analysis/AnalysisContext";
import PipelineStrip from "@/components/analysis/PipelineStrip";
import ReportChecks from "@/components/analysis/ReportChecks";
import { formatStageDuration, stageTiming } from "@/components/analysis/stageTimeline";
import { jobStopNote } from "@/lib/runFailure";
import { correctionLine } from "./correctionLine";
import type { FpWarning, MalwareReport, NoToolCallAsk } from "@/types/malware-report";

/**
 * How the run itself went, for the reader who asks: the shape of the team and
 * its stages, the verdict's own notes, a degraded run's reasons, the report's
 * QA warnings, the evidence counts, the time per stage, what the report's
 * checks left standing and the run record.
 *
 * One collapsed section under Evidence and nowhere else. None of it is a
 * finding about the sample, and a reader of the findings is told in plain
 * words under the header when the run was not whole.
 */
export default function RunQuality() {
  const { report, job, jobId } = useReport();
  const run = useRun(jobId || null);
  const mr = report?.malware_report ?? null;

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
  /* The linter writes one explanation per rule, so a run that tripped one rule
     three times carried the same paragraph three times. Said once where they
     agree, listed where they do not. */
  const explanations = [
    ...new Set(fpWarnings.map((w) => (w.explanation ?? "").trim()).filter(Boolean)),
  ];
  const sharedExplanation = explanations.length === 1 ? explanations[0] : null;
  const evidence = runSummary?.evidence ?? null;
  const ungroundedSections = runSummary?.sections_without_evidence ?? 0;
  const headline = verdictHeadline(
    report?.verdict,
    report?.overall_confidence,
    assessedSeverity(mr),
  );
  const readingNote = verdictReadingNote(report?.verdict_reading);
  const stopNote = jobStopNote(job?.status, job?.error_message);
  const profile = (runSummary as {
    profile?: { name?: string; analysts?: string[] } | null;
  } | null)?.profile;
  const profileName = profile?.name;
  const profileAnalysts = profile?.analysts ?? [];

  return (
    <Section title="Run quality" collapsible defaultOpen={false}>
      <div className="flex flex-col gap-4" data-testid="run-quality">
        <div>
          <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">Stages</h3>
          {/* Which analyst line-up produced the report: a `lean` run (network
              only) reads as a full one otherwise, the deterministic static
              layers being present either way. The default line-up and a
              report stored before profiles existed say nothing. */}
          {profileName && profileName !== "default" && (
            <p className="mb-1.5 text-xs text-text-secondary">
              <span
                className="rounded bg-accent/10 px-2 py-0.5 text-accent-strong"
                title={profileAnalysts.length > 0 ? `Analysts: ${profileAnalysts.join(", ")}` : undefined}
              >
                Profile: {profileName}
              </span>
              {profileAnalysts.length > 0 && <span className="ml-2">Analysts: {profileAnalysts.join(", ")}</span>}
            </p>
          )}
          <PipelineStrip stages={run.stages} roster={run.roster} />
        </div>

        {report && (
          <div className="text-xs text-text-secondary space-y-1" data-testid="verdict-notes">
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">Verdict</h3>
            <p className={headline.conflict ? "text-status-orange" : undefined}>{headline.text}</p>
            {headline.conflict && <p className="text-status-orange">{VERDICT_CONFLICT_NOTE}</p>}
            {readingNote && <p className="text-status-orange">{readingNote}</p>}
            {/* The run's own words for why it is not whole, which the
                remarks under the header say only generically. */}
            {report.incomplete_reason && (
              <p className="text-status-orange" data-testid="incomplete-reason">
                {report.incomplete_reason}
              </p>
            )}
            {stopNote && stopNote !== report.incomplete_reason && <p>{stopNote}</p>}
          </div>
        )}
        {!report && stopNote && <p className="text-xs text-text-secondary">{stopNote}</p>}

        {isDegraded && (
          <div
            role="alert"
            className="flex items-start gap-3 rounded border border-status-orange/40 bg-status-orange/10 p-3 text-sm"
          >
            <span className="font-semibold text-status-orange shrink-0">
              DEGRADED RUN
            </span>
            <div className="text-text-secondary space-y-1">
              <p>{degradedBannerText(report?.verdict_reading, report?.overall_confidence)}</p>
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
            className="rounded border border-status-orange/40 bg-status-orange/10 p-3 text-sm"
          >
            {/* `display:flex` on the `<summary>` itself suppresses Chromium's
                disclosure triangle, so this box gave no sign that it opened
                while the RUN RECORD beside it did. The flex row is a child. */}
            <summary className="cursor-pointer select-none">
              <span className="inline-flex items-center gap-3 align-middle">
                <span className="font-semibold text-status-orange">
                  QA WARNINGS
                </span>
                <span className="text-xs text-text-muted">
                  {countLabel(fpWarnings.length, "finding")}
                  {hasErrorWarning ? " (errors present)" : ""}
                </span>
              </span>
            </summary>
            <ul className="mt-2 space-y-2 text-text-secondary">
              {fpWarnings.map((w, i) => (
                <li key={i} className="space-y-0.5">
                  {/* The field is named in the sentence rather than repeated
                      under it as `field: defensive_recommendations[1]`, which
                      restated what the message had just said. */}
                  <p className="text-xs">
                    <code className="font-mono font-semibold">{w.rule}</code>{" "}
                    <span className="uppercase text-text-muted">
                      [{w.severity}]
                    </span>{" "}
                    {w.message}
                    {w.field ? (
                      <>
                        {" "}
                        <span className="text-text-muted">
                          (at <code className="font-mono">{w.field}</code>)
                        </span>
                      </>
                    ) : null}
                  </p>
                </li>
              ))}
            </ul>
            {/* One explanation for the group. Each warning used to carry its
                own copy of the same two sentences, verbatim, three times over. */}
            {sharedExplanation ? (
              <p className="mt-2 text-[11px] text-text-muted">{sharedExplanation}</p>
            ) : (
              <ul className="mt-2 space-y-1">
                {explanations.map((text, i) => (
                  <li key={i} className="text-[11px] text-text-muted">
                    {text}
                  </li>
                ))}
              </ul>
            )}
          </details>
        )}

        {/* What the report is standing on. Counted at build time from the
            evidence, so it says how much of the report is checkable and how
            much of it is not — a section with neither an evidence record nor a
            named finding behind it is a defect, and this is where it shows. */}
        {evidence && (
          <div className="bg-bg-surface border border-border rounded">
            <div className="px-4 py-3 border-b border-border flex items-center gap-3">
              <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
                Evidence
              </h2>
            </div>
            <div className="p-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 text-center">
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
                {ungroundedSections === 1 ? "section names" : "sections name"} neither an evidence
                record nor the finding it came from, so nothing in the console can resolve it.
              </p>
            )}
          </div>
        )}

        <StageTimingCard jobId={jobId} elapsedSeconds={job?.duration_seconds ?? null} />

        {mr && <ReportChecks mr={mr} />}

        {/* How the run was set up and what it spent, in the one place that
            answers it: the job's own configuration, and the parts of the run
            summary no other block here says. */}
        <RunRecord runSummary={runSummary} config={job?.config ?? null} />
      </div>
    </Section>
  );
}

/**
 * Where the run's time went, stage by stage.
 *
 * Read from the run store's stage rows — the ones the header strip draws — so
 * the two can never print different durations for one stage. Only stages that
 * took time get a row, and the card is absent for a run stored before stages
 * were timed. The total elapsed is the job's, the same figure the header's
 * Duration prints, and the gap between it and the stages is time spent outside
 * any stage.
 */
function StageTimingCard({
  jobId,
  elapsedSeconds,
}: {
  jobId: string;
  elapsedSeconds: number | null;
}) {
  const run = useRun(jobId || null);
  const { stages, stagesMs } = stageTiming(run.stages, elapsedSeconds);
  if (stages.length === 0) return null;
  const names = rosterNames(run.roster);

  return (
    <section
      aria-labelledby="stage-timing-heading"
      className="bg-bg-surface border border-border rounded"
    >
      <div className="px-4 py-3 border-b border-border flex flex-wrap items-baseline gap-x-4 gap-y-1">
        <h2
          id="stage-timing-heading"
          className="text-xs font-medium text-text-primary uppercase tracking-wider"
        >
          Time per stage
        </h2>
        {elapsedSeconds ? (
          <p className="text-xs text-text-secondary">
            <span className="text-text-muted">Total elapsed: </span>
            <span className="font-mono">{formatDuration(elapsedSeconds)}</span>
            <span className="text-text-muted"> · in stages: </span>
            <span className="font-mono">{formatStageDuration(stagesMs)}</span>
          </p>
        ) : (
          <p className="text-xs text-text-secondary">
            <span className="text-text-muted">In stages: </span>
            <span className="font-mono">{formatStageDuration(stagesMs)}</span>
          </p>
        )}
      </div>
      <ul className="p-4 space-y-2">
        {stages.map((stage) => (
          <li
            key={stage.key}
            className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)_auto] items-center gap-3 text-xs"
          >
            <span className="text-text-secondary truncate" title={names.stage(stage.key)}>
              {names.stage(stage.key)}
            </span>
            <span aria-hidden="true" className="h-2 bg-bg-active rounded-sm">
              <span
                className="block h-2 bg-accent rounded-sm"
                style={{ width: `${stage.share}%` }}
              />
            </span>
            <span className="font-mono text-text-primary text-right">{stage.label}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** A job-config value as one line: a string as itself, anything else as JSON. */
function configValue(value: unknown): string {
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

/**
 * What this run was told to do, and what it spent doing it.
 *
 * Folded shut, because it answers a question a reader asks about one run in
 * twenty — why this one used that sandbox, how many correction turns the
 * producers needed — and never the first question about a report. Only the
 * facts no other block carries: the stages are the strip above, the evidence
 * counts are the block above, and the degradation reasons are the banner at
 * the top.
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
  const toolAsks = Object.entries(runSummary.nudge?.no_tool_call ?? {});
  const bundleLoss = bundleLossSentence(runSummary.truncation ?? null);
  const partialGrounding = partialGroundingSentence(runSummary.truncation ?? null);
  const corpusHeld = corpusHeldSentence(runSummary.truncation ?? null);
  const spent = tokensSentence(runSummary.tokens ?? null);
  const fallbacks = Object.entries(runSummary.models ?? {}).flatMap(([agent, block]) =>
    (block?.fallbacks ?? []).map((row) => ({ agent, reason: row.reason })),
  );
  const rests = runSummary.server_rests ?? [];
  const operatorChoices = runSummary.operator_choices ?? [];
  const enrichmentAsked = enrichmentAsks(runSummary);
  const configRows = Object.entries(config ?? {});

  return (
    <details className="bg-bg-surface border border-border rounded">
      <summary className="px-4 py-3 cursor-pointer select-none text-xs font-medium text-text-primary uppercase tracking-wider">
        Run record
      </summary>
      <div className="px-4 pb-4 grid grid-cols-1 md:grid-cols-2 gap-6 text-xs text-text-secondary">
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
          {/* What the configuration left out (a key never set, a server
              switched off, a tool a shared server withholds by policy). It
              cost the run no evidence it would have had, so it is listed
              here and never in the DEGRADED RUN banner. */}
          {operatorChoices.length > 0 && (
            <>
              <h3 className="text-[11px] uppercase tracking-wider text-text-muted mt-3 mb-1.5">
                Not configured or withheld by choice
              </h3>
              <ul className="space-y-1" data-testid="operator-choices">
                {operatorChoices.map((reason, i) => (
                  <li key={`choice-${i}`} className="text-text-muted break-words">
                    {reason}
                  </li>
                ))}
              </ul>
            </>
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
              {correctionLine(validation, countLabel)}
            </li>
            {spent && <li>{spent}</li>}
            {fallbacks.map((row, i) => (
              <li key={`fallback-${i}`} className="text-text-muted">
                {row.agent} fell back to another model — {row.reason}.
              </li>
            ))}
            {rests.map((row, i) => (
              <li key={`rest-${i}`} className="text-status-orange">
                {serverRestSentence(row)}
              </li>
            ))}
            {enrichmentAsked.map((row, i) => (
              <li
                key={`enrichment-asked-${i}`}
                className={row.errored || row.failed ? "text-status-orange" : "text-text-muted"}
                data-testid="enrichment-asked"
              >
                Enrichment asked {enrichmentAskSentence(row)}.
              </li>
            ))}
            {bundleLoss && <li className="text-text-muted">{bundleLoss}</li>}
            {partialGrounding && <li className="text-text-muted">{partialGrounding}</li>}
            {corpusHeld && <li className="text-text-muted">{corpusHeld}</li>}
            {(validation?.unresolved ?? []).map((item, i) => (
              <li key={i} className={validationRowClass(item)}>
                {validationRowText(item)}
              </li>
            ))}
            {retryMode.map(([agent, mode]) => (
              <li key={agent} className="text-text-muted">
                {agent} needed the final-answer nudge sent as {mode}.
              </li>
            ))}
            {toolAsks.flatMap(([agent, asks]) =>
              asks.map((ask, i) => (
                <li key={`tool-ask-${agent}-${i}`} className="text-text-muted">
                  {noToolCallSentence(agent, ask)}
                </li>
              )),
            )}
          </ul>
        </div>
      </div>
    </details>
  );
}

function noToolCallSentence(agent: string, ask: NoToolCallAsk): string {
  const head = `${agent} answered without calling a tool and was asked once whether to call one`;
  if (ask.followed === "called_tools") {
    return `${head}; it then made ${ask.tool_calls_after} tool call(s).`;
  }
  if (ask.followed === "answered_without_tools") {
    return `${head}; it answered again without calling one.`;
  }
  return `${head}; no answer followed.`;
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
