"use client";

import { useId, useState, type ReactNode } from "react";
import { ChevronRight } from "lucide-react";
import type { ReportDetailDTO } from "@/lib/api";
import { prettyName } from "@/lib/conversation";
import { rosterNames, type RosterNames } from "@/lib/rosterNames";
import { useReport } from "./AnalysisContext";
import AgentReport from "./AgentReport";
import CitedProse from "./CitedProse";
import SafeMarkdown from "./SafeMarkdown";
import StructuredValue from "./StructuredValue";
import {
  analystKey,
  debateOutcome,
  debateRounds,
  hasDebate,
  parseAgentReport,
  type ContestedLine,
  type DebateAnswer,
  type DebateOutcome,
  type DebateRound,
  type LineStanding,
} from "./debate";
import { keepBackslashes } from "./safeMarkdown";

/**
 * The Debate view under Evidence: how the analysts argued their findings out.
 *
 * The outcome leads, as the sentence a reader wants first. Then one row per
 * mediation round, the last one open: the mediator's reading, each line it
 * listed (who must revise, the contested point, whether it blocks agreement
 * and why, what the ledger states for it), and every analyst's revision that
 * answered it, with the points it disputed. Last, each analyst's final
 * report, opened one at a time.
 *
 * The Analyst discussion beside it is the same run in the order things were
 * said; this view is the same run by the questions that were argued.
 * Model-written words (the mediator's reading, a contested point, an
 * analyst's prose) are drawn as Markdown with their backslashes kept; what
 * the platform wrote (the ledger's facts, an answer's summary line) and an
 * analyst's claims stay literal.
 */
export default function DebateView({ report }: { report: ReportDetailDTO }) {
  const { job } = useReport();
  const names = rosterNames(job?.roster, prettyName);
  const summary = report.malware_report?.negotiation_summary ?? null;
  const log = report.negotiation_log;
  const outcome = debateOutcome(summary, log);
  const rounds = debateRounds(log, report.transcript);
  const reports = Object.entries(report.agent_reports ?? {}).filter(
    (entry): entry is [string, string] => typeof entry[1] === "string" && entry[1].trim() !== "",
  );

  return (
    <div className="space-y-10">
      <Outcome outcome={outcome} recorded={hasDebate(summary, log)} />
      <Block id="debate-rounds" title="Rounds" count={rounds.length || undefined}>
        {rounds.length === 0 ? (
          <p className="text-sm text-text-muted">
            {hasDebate(summary, log)
              ? "No mediation round was recorded, so there are no contested lines to show."
              : "This run recorded no debate between its analysts."}
          </p>
        ) : (
          <div className="divide-y divide-border-light rounded-md border border-border bg-bg-surface">
            {rounds.map((round, i) => (
              <RoundRow key={`${round.round}-${i}`} round={round} names={names} startOpen={i === rounds.length - 1} />
            ))}
          </div>
        )}
      </Block>
      <Block id="debate-reports" title="Each analyst's report" count={reports.length || undefined}>
        {reports.length === 0 ? (
          <p className="text-sm text-text-muted">No analyst report was stored with this run.</p>
        ) : (
          <>
            <p className="max-w-[75ch] text-sm text-text-secondary">
              The last report each analyst wrote, after any revision it made in the debate.
            </p>
            <div className="divide-y divide-border-light rounded-md border border-border bg-bg-surface">
              {reports.map(([agent, text]) => (
                <ReportRow key={agent} agent={agent} label={names.agent(agent)} text={text} />
              ))}
            </div>
          </>
        )}
      </Block>
    </div>
  );
}

function Block({ id, title, count, children }: { id: string; title: string; count?: number; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-heading`} className="scroll-mt-16 space-y-3">
      <h2 id={`${id}-heading`} className="text-base font-semibold text-text-primary">
        {title}
        {count != null && <span className="ml-1.5 text-sm font-normal text-text-muted tabular-nums">{count}</span>}
      </h2>
      {children}
    </section>
  );
}

function percent(n: number | null): string {
  return n === null ? "" : `${Math.round(n * 100)}%`;
}

/* ── The outcome ───────────────────────────────────────────────────── */

function Outcome({ outcome, recorded }: { outcome: DebateOutcome; recorded: boolean }) {
  if (!recorded) {
    return (
      <Block id="debate-outcome" title="How the debate ended">
        <p className="text-sm text-text-muted">
          No debate was recorded: the report holds neither a negotiation log nor a summary of one.
        </p>
      </Block>
    );
  }
  const facts: [string, ReactNode][] = [];
  // The sentence states the rounds when it states how the debate ended.
  if (outcome.rounds !== null && !outcome.ending) facts.push(["Rounds", outcome.rounds]);
  if (outcome.consensus !== null) facts.push(["Consensus", outcome.consensus ? "Reached" : "Not reached"]);
  if (outcome.confidenceHistory.length > 0) {
    facts.push([
      "Mean claim confidence by round",
      <span key="h" className="tabular-nums">
        {outcome.confidenceHistory.map(percent).join(", ")}
      </span>,
    ]);
  }
  if (outcome.finalConfidence !== null) facts.push(["Mediator's last confidence", <span key="f" className="tabular-nums">{percent(outcome.finalConfidence)}</span>]);
  if (outcome.sycophancy !== null) {
    facts.push([
      "Agreement without new evidence",
      outcome.sycophancy === 0 ? "Not flagged" : `Flagged in ${outcome.sycophancy} round${outcome.sycophancy === 1 ? "" : "s"}`,
    ]);
  }
  if (outcome.mediationFailed) facts.push(["Mediation", <span key="m" className="text-status-red">A round failed</span>]);
  const sentence = outcome.ending
    ? `${outcome.ending}${outcome.rounds !== null ? `, after ${outcome.rounds} round${outcome.rounds === 1 ? "" : "s"}` : ""}.`
    : "The report does not say how the debate ended.";
  return (
    <Block id="debate-outcome" title="How the debate ended">
      <p className="max-w-[75ch] text-[15px] leading-7 text-text-primary">{sentence}</p>
      {facts.length > 0 && (
        <dl className="grid max-w-2xl grid-cols-[minmax(0,14rem)_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-sm">
          {facts.map(([term, value]) => (
            <div key={term} className="contents">
              <dt className="text-text-secondary">{term}</dt>
              <dd className="min-w-0 text-text-primary">{value}</dd>
            </div>
          ))}
        </dl>
      )}
      {Object.keys(outcome.other).length > 0 && (
        <div className="max-w-2xl">
          <h3 className="mb-1 text-xs font-medium text-text-secondary">More of the summary</h3>
          <StructuredValue value={outcome.other} name="Debate summary" />
        </div>
      )}
    </Block>
  );
}

/* ── One round ─────────────────────────────────────────────────────── */

function roundGist(round: DebateRound): string {
  const blocking = round.lines.filter((l) => l.standing === "blocking").length;
  const other = round.lines.length - blocking;
  const parts: string[] = [];
  if (round.lines.length === 0) parts.push(round.noneListed ? "no contradiction listed" : "no lines listed");
  else {
    if (blocking) parts.push(`${blocking} blocking`);
    if (other) parts.push(`${other} not blocking`);
  }
  parts.push(`${round.answers.length} answer${round.answers.length === 1 ? "" : "s"}`);
  return parts.join(", ");
}

function RoundRow({ round, names, startOpen }: { round: DebateRound; names: RosterNames; startOpen: boolean }) {
  const [open, setOpen] = useState(startOpen);
  const bodyId = useId();
  const failed = round.status !== "complete";
  const label = `Round ${round.round}`;
  return (
    <section aria-label={label}>
      <h3>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => setOpen((v) => !v)}
          className="flex w-full flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-3 text-left hover:bg-bg-hover focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
        >
          <ChevronRight
            aria-hidden="true"
            className={`h-3.5 w-3.5 shrink-0 self-center text-text-muted motion-safe:transition-transform ${open ? "rotate-90" : ""}`}
          />
          <span className="text-sm font-semibold text-text-primary">{label}</span>
          <span className="text-sm text-text-secondary">{roundGist(round)}</span>
          {round.confidence !== null && (
            <span className="text-xs text-text-muted tabular-nums">mediator {percent(round.confidence)} confident</span>
          )}
          {failed && <span className="text-xs text-status-red">{round.status === "timeout" ? "timed out" : round.status}</span>}
        </button>
      </h3>
      {open && (
        <div id={bodyId} className="space-y-5 px-4 pb-5 sm:pl-11">
          {round.words && (
            <div className="space-y-1">
              <h4 className="text-xs font-medium text-text-secondary">{round.agent}&apos;s reading</h4>
              <SafeMarkdown
                markdown={keepBackslashes(round.words)}
                cite
                regionName={`${label} reading`}
                className="max-w-[75ch] space-y-3 text-sm leading-6 text-text-primary"
              />
            </div>
          )}
          {round.note && <p className="text-xs text-text-secondary">{round.note}</p>}
          {round.notices.map((notice, i) => (
            <p key={i} className="max-w-[75ch] whitespace-pre-wrap break-words text-xs text-status-orange">
              {notice}
            </p>
          ))}
          <div className="space-y-1">
            <h4 className="text-xs font-medium text-text-secondary">Contested lines</h4>
            {round.lines.length === 0 ? (
              <p className="text-sm text-text-muted">
                {round.noneListed
                  ? "The mediator listed no contradiction in this round."
                  : "The mediator listed no line this view can read apart; its whole answer is above."}
              </p>
            ) : (
              <ol className="divide-y divide-border-light">
                {round.lines.map((line, i) => (
                  <LineRow key={i} line={line} names={names} name={`${label} line ${i + 1}`} />
                ))}
              </ol>
            )}
          </div>
          <div className="space-y-1">
            <h4 className="text-xs font-medium text-text-secondary">Answers</h4>
            {round.answers.length === 0 ? (
              <p className="text-sm text-text-muted">No analyst revised its findings in answer to this round.</p>
            ) : (
              <ul className="divide-y divide-border-light">
                {round.answers.map((answer, i) => (
                  <AnswerRow key={`${answer.speaker}-${i}`} answer={answer} names={names} name={`${label} answer of ${answer.speaker}`} />
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </section>
  );
}

const STANDING: Record<LineStanding, { word: string; glyph: string; text: string }> = {
  blocking: { word: "Blocking", glyph: "bg-status-orange border-status-orange", text: "text-status-orange" },
  "not-blocking": { word: "Not blocking", glyph: "border-text-muted bg-transparent", text: "text-text-secondary" },
  unmarked: { word: "Mark not read", glyph: "border-dashed border-text-muted bg-transparent", text: "text-text-muted" },
};

function markerWords(marker: string): string {
  if (marker === "new") return "New this round";
  const carried = /^carried:\s*(.*)$/.exec(marker);
  return carried ? `Carried over (${carried[1]})` : marker;
}

function LineRow({ line, names, name }: { line: ContestedLine; names: RosterNames; name: string }) {
  const [facts, setFacts] = useState(false);
  const factsId = useId();
  const standing = STANDING[line.standing];
  const asked = line.analysts.map((a) => names.agent(analystKey(a)));
  return (
    <li className="space-y-1.5 py-3">
      <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs">
        <span className={`inline-flex items-center gap-1.5 font-medium ${standing.text}`}>
          <span aria-hidden="true" className={`inline-block h-2 w-2 rounded-full border ${standing.glyph}`} />
          {standing.word}
        </span>
        {line.markers.map((m) => (
          <span key={m} className="text-text-muted">
            {markerWords(m)}
          </span>
        ))}
        {asked.length > 0 && <span className="text-text-secondary">Asked to revise: {asked.join(", ")}</span>}
      </p>
      <SafeMarkdown
        markdown={keepBackslashes(line.text)}
        cite
        regionName={name}
        className="max-w-[75ch] space-y-2 text-sm leading-6 text-text-primary"
      />
      {line.reason && (
        <p className="max-w-[75ch] text-xs leading-5 text-text-secondary">
          <span className="text-text-muted">Why {line.standing === "blocking" ? "it blocks" : "it does not block"}: </span>
          <CitedProse text={line.reason} />
        </p>
      )}
      {line.facts && (
        <div>
          <button
            type="button"
            aria-expanded={facts}
            aria-controls={factsId}
            onClick={() => setFacts((v) => !v)}
            className="text-xs text-accent-strong hover:underline"
          >
            {facts ? "Hide" : "Show"} what the ledger states for this line
          </button>
          {facts && (
            <p id={factsId} className="mt-1 max-w-[75ch] whitespace-pre-wrap break-words text-xs leading-5 text-text-secondary">
              <CitedProse text={line.facts} />
            </p>
          )}
        </div>
      )}
    </li>
  );
}

function AnswerRow({ answer, names, name }: { answer: DebateAnswer; names: RosterNames; name: string }) {
  const [open, setOpen] = useState(false);
  const reportId = useId();
  const who = answer.displayName || names.agent(answer.speaker);
  return (
    <li className="space-y-1.5 py-3">
      <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="text-sm font-medium text-text-primary">{who}</span>
        {answer.confidence !== null && <span className="text-xs text-text-muted tabular-nums">{percent(answer.confidence)}</span>}
        {answer.status !== "complete" && <span className="text-xs text-status-red">{answer.status}</span>}
      </p>
      {/* The platform's line about the revision, as it wrote it. */}
      <p className="max-w-[75ch] whitespace-pre-wrap break-words text-sm leading-6 text-text-secondary">
        <CitedProse text={answer.text} />
      </p>
      {answer.dissent.length > 0 && (
        <div>
          <h5 className="text-xs font-medium text-text-secondary">Disputed</h5>
          <ul className="mt-1 max-w-[75ch] list-disc space-y-1 pl-5 text-xs leading-5 text-text-primary">
            {answer.dissent.map((d, i) => (
              <li key={i} className="whitespace-pre-wrap break-words">
                <CitedProse text={d} />
              </li>
            ))}
          </ul>
        </div>
      )}
      {answer.report && (
        <div>
          <button
            type="button"
            aria-expanded={open}
            aria-controls={reportId}
            onClick={() => setOpen((v) => !v)}
            className="text-xs text-accent-strong hover:underline"
          >
            {open ? "Hide" : "Read"} this answer in full
          </button>
          {open && (
            <div id={reportId} className="mt-2">
              <AgentReport report={answer.report} name={name} truncated={answer.reportTruncated} />
            </div>
          )}
        </div>
      )}
    </li>
  );
}

/* ── Each analyst's report ─────────────────────────────────────────── */

function ReportRow({ agent, label, text }: { agent: string; label: string; text: string }) {
  const [open, setOpen] = useState(false);
  const bodyId = useId();
  const parsed = parseAgentReport(text);
  const gist: string[] = [];
  if (parsed.round !== null) gist.push(`round ${parsed.round}`);
  if (parsed.claims.length > 0) gist.push(`${parsed.claims.length} claim${parsed.claims.length === 1 ? "" : "s"}`);
  if (parsed.meanConfidence !== null) gist.push(`mean confidence ${percent(parsed.meanConfidence)}`);
  return (
    <section aria-label={`Report of ${label}`}>
      <h3>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => setOpen((v) => !v)}
          className="flex w-full flex-wrap items-baseline gap-x-3 gap-y-1 px-4 py-3 text-left hover:bg-bg-hover focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
        >
          <ChevronRight
            aria-hidden="true"
            className={`h-3.5 w-3.5 shrink-0 self-center text-text-muted motion-safe:transition-transform ${open ? "rotate-90" : ""}`}
          />
          <span className="text-sm font-semibold text-text-primary">{label}</span>
          {gist.length > 0 && <span className="text-sm text-text-secondary">{gist.join(", ")}</span>}
        </button>
      </h3>
      {open && (
        <div id={bodyId} className="px-4 pb-5 sm:pl-11">
          <AgentReport report={text} name={`Report of ${agent}`} />
        </div>
      )}
    </section>
  );
}
