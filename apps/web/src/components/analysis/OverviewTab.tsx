"use client";

import { useEffect, useMemo, useState, type ReactNode } from "react";
import Link from "next/link";
import CopyButton from "@/components/ui/CopyButton";
import { kpiState } from "@/components/ui/KpiTile";
import { SeverityPill } from "@/components/ui/Pill";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import { countLabel, formatBytes, formatDateTime, truncateMiddle } from "@/lib/report-utils";
import { useRun } from "@/lib/useRun";
import { PRIORITY_STYLES, type DefensiveCategory, type FollowUp, type MalwareReport } from "@/types/malware-report";
import { useReport } from "./AnalysisContext";
import BasisMark, { BasisGlyph } from "./BasisMark";
import { CiteMark } from "./CitedProse";
import EvidenceChips from "./EvidenceChips";
import PipelineStrip from "./PipelineStrip";
import ReportAbsent from "./ReportAbsent";
import { ScrollToAnchor } from "./ReportGate";
import SafeMarkdown from "./SafeMarkdown";
import { reportAbsence } from "./reportAbsence";
import { FOLLOW_UP_EVENT, canAskFollowUp, followUpRows } from "./followUps";
import { indicatorRows } from "./indicators";
import { keyFindings, noSummaryReason, outcomeLine, questionAnswers } from "./reportProse";
import {
  VOICE_BASIS,
  VOICE_TEXT,
  analysisHref,
  claimBasis,
  configText,
  fileKind,
  findingRows,
  howObtained,
  kpis,
  proseText,
  referenceRows,
  sortedRecommendations,
  techniqueIdsIn,
  techniqueVoices,
  type Basis,
  type FindingRow,
} from "./overview";

/**
 * Overview: the page a reader lands on.
 *
 * Two columns that share the width. The reading column says each thing
 * once: the bottom line (the executive summary), the key findings as rows
 * that each carry how they are known and the techniques they name, the
 * answers to the questions the analysis was asked, the longer account where
 * the report wrote one, and the configuration it extracted. The facts rail
 * beside it holds what a responder acts on and checks: what to do now, the
 * severity and why, the indicators to block, every behaviour and technique
 * split by whether the sandbox saw it, the counts, the file, the external
 * references, and the questions asked since. Below ~1000 px of content the rail stacks under the
 * column; on a very wide screen its blocks flow into two columns so the
 * width is used rather than left empty.
 */

const FIRST_KEY_FINDINGS = 8;
const FIRST_ACTIONS = 3;
const FIRST_INDICATORS = 5;
const FIRST_PER_GROUP = 6;

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
  const { jobId, report, job, loading, reportError } = useReport();

  if (loading) return <p className="text-sm text-text-muted">Loading the analysis…</p>;
  const absent = reportAbsence({ report, job, reportError });
  if (absent) {
    return absent.kind === "running" ? <RunningOverview jobId={jobId} text={absent.text} /> : <ReportAbsent absence={absent} />;
  }
  const mr = report?.malware_report ?? null;
  if (!report || !mr) return <LegacyOverview />;

  return (
    <div className="grid items-start gap-x-10 gap-y-8 @[62rem]:grid-cols-[minmax(0,1fr)_22rem] @[100rem]:grid-cols-[minmax(0,60rem)_minmax(0,1fr)]">
      <div className="min-w-0 space-y-9">
        <BottomLine mr={mr} />
        <KeyFindings mr={mr} />
        <QuestionAnswers mr={mr} />
        <Narrative mr={mr} />
        <Configuration mr={mr} />
      </div>
      <aside
        aria-label="Facts"
        className="min-w-0 rounded-md border border-border bg-bg-surface @[100rem]:columns-2 @[100rem]:gap-0"
      >
        <ActNow mr={mr} />
        <Severity mr={mr} />
        <TopIndicators mr={mr} jobId={jobId} />
        <Behaviours mr={mr} />
        <Counts mr={mr} />
        <FileFacts mr={mr} />
        <References mr={mr} />
        <FollowUpsLine jobId={jobId} status={job?.status} />
      </aside>
      <ScrollToAnchor />
    </div>
  );
}

/* ── Reading column ────────────────────────────────────────────────── */

/** A block of the reading column: a heading and what it says. */
function Block({ title, count, actions, children, id }: { title: string; count?: number; actions?: ReactNode; children: ReactNode; id?: string }) {
  const headingId = `${id ?? title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-heading`;
  return (
    <section aria-labelledby={headingId} id={id} className="scroll-mt-16">
      <div className="mb-3 flex items-baseline justify-between gap-3">
        <h2 id={headingId} className="text-base font-semibold text-text-primary">
          {title}
          {count != null && " "}{count != null && <span className="ml-1 text-sm font-normal text-text-muted tabular-nums">{count}</span>}
        </h2>
        {actions}
      </div>
      {children}
    </section>
  );
}

function BottomLine({ mr }: { mr: MalwareReport }) {
  const summary = mr.executive_summary?.trim() ?? "";
  const absentBecause = noSummaryReason(mr);
  return (
    <Block title="Bottom line">
      {summary ? (
        <SafeMarkdown
          markdown={summary}
          cite
          regionName="Bottom line"
          className="max-w-[75ch] space-y-3 text-[15px] leading-7 text-text-primary"
        />
      ) : (
        <p className="text-sm text-text-muted">
          {absentBecause ? `No summary was written: ${absentBecause}.` : "The report holds no summary."}
        </p>
      )}
    </Block>
  );
}

function KeyFindings({ mr }: { mr: MalwareReport }) {
  const { showEvidence } = useReport();
  const [all, setAll] = useState(false);
  const findings = keyFindings(mr);
  const rows = useMemo(() => findingRows(mr), [mr]);
  const voices = useMemo(() => techniqueVoices(mr), [mr]);
  const byTechnique = useMemo(() => new Map(rows.filter((r) => r.id.startsWith("ttp-")).map((r) => [r.techniques[0], r])), [rows]);
  if (findings.length === 0) return null;
  const shown = all ? findings : findings.slice(0, FIRST_KEY_FINDINGS);
  return (
    <Block title="Key findings" count={findings.length}>
      <ul className="border-t border-border-light">
        {shown.map((f, i) => {
          const techniques = techniqueIdsIn(f.text);
          const basis = claimBasis(techniques, voices);
          return (
            <li
              key={`${i}-${f.text}`}
              className="grid gap-x-6 gap-y-2 border-b border-border-light py-3 @[44rem]:grid-cols-[minmax(0,1fr)_12rem]"
            >
              <div className="max-w-[80ch] text-sm leading-6 text-text-primary">
                <SafeMarkdown markdown={f.text} cite inline regionName={`Key finding ${i + 1}`} className="" />
                {f.evidence_ids.length > 0 && <CiteMark ids={f.evidence_ids} title={`Evidence for key finding ${i + 1}`} />}
              </div>
              <div className="flex flex-col items-start gap-1.5 pt-0.5">
                {basis && <BasisMark basis={basis.basis} label={basis.label} detail={basis.detail} />}
                {techniques.length > 0 && (
                <div className="flex flex-wrap gap-1">
                {techniques.map((t) => {
                  const row = byTechnique.get(t);
                  return row ? (
                    <TechniqueChip key={t} row={row} onOpen={(el) => openRow(showEvidence, row, el)} />
                  ) : (
                    <span key={t} className="rounded border border-border-light px-1 font-mono text-[11px] text-text-muted" title="Not among the techniques this report maps">
                      {t}
                    </span>
                  );
                })}
                </div>
                )}
              </div>
            </li>
          );
        })}
      </ul>
      {findings.length > FIRST_KEY_FINDINGS && (
        <button type="button" onClick={() => setAll((v) => !v)} className="mt-2 text-xs text-accent-strong hover:underline">
          {all ? `Show the first ${FIRST_KEY_FINDINGS}` : `Show ${findings.length - FIRST_KEY_FINDINGS} more key findings`}
        </button>
      )}
    </Block>
  );
}

function openRow(
  showEvidence: ReturnType<typeof useReport>["showEvidence"],
  row: FindingRow,
  opener: HTMLElement,
) {
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
}

/** A technique id as a small chip that opens its evidence, with its basis glyph. */
function TechniqueChip({ row, onOpen }: { row: FindingRow; onOpen: (el: HTMLElement) => void }) {
  const basis = VOICE_BASIS[row.voice];
  return (
    <button
      type="button"
      onClick={(e) => onOpen(e.currentTarget)}
      title={`${row.title}: ${VOICE_TEXT[row.voice]}`}
      aria-label={`${row.techniques[0]} ${row.title}, ${basis.label}: show evidence`}
      className="inline-flex items-center gap-1 rounded border border-border bg-bg-elevated px-1.5 font-mono text-[11px] leading-5 text-text-secondary hover:border-text-muted hover:text-text-primary"
    >
      <BasisGlyph basis={basis.basis} />
      {row.techniques[0]}
    </button>
  );
}

/* Each question the analysis was asked when it was submitted, the outcome the
 * report stands by and its answer. Nothing is drawn for an analysis asked
 * nothing. */
function QuestionAnswers({ mr }: { mr: MalwareReport }) {
  const answers = questionAnswers(mr);
  if (answers.length === 0) return null;
  return (
    <Block title="Your questions" count={answers.length}>
      <ol className="max-w-[75ch] space-y-5">
        {answers.map((answer, i) => (
          <li key={i} className="space-y-1.5">
            <p className="text-sm font-medium text-text-primary">
              Q{i + 1}. {answer.question}
            </p>
            <p className="text-xs">
              <span className="mr-2 text-text-muted">Outcome</span>
              <span className={answer.answered ? "text-status-orange" : "text-text-secondary"}>{outcomeLine(answer)}</span>
            </p>
            {answer.answer.trim() && (
              <div className="text-sm leading-6 text-text-secondary">
                <SafeMarkdown markdown={answer.answer} cite regionName={`Answer ${i + 1}`} className="space-y-2" />
                <EvidenceChips ids={answer.evidence_ids} />
              </div>
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
    </Block>
  );
}

/* The longer account of what the sample can do, where the report wrote one. */
function Narrative({ mr }: { mr: MalwareReport }) {
  const paragraphs = (mr.capabilities_narrative ?? []).filter((p) => p?.trim());
  if (paragraphs.length === 0) return null;
  return (
    <Block title="What it can do">
      <div className="max-w-[75ch] space-y-3">
        {paragraphs.map((para, i) => (
          <SafeMarkdown key={i} markdown={para} cite regionName={`What it can do ${i + 1}`} className="space-y-2 text-sm leading-6 text-text-secondary" />
        ))}
      </div>
    </Block>
  );
}

function Configuration({ mr }: { mr: MalwareReport }) {
  const config = mr.technical_analysis?.configuration ?? [];
  if (config.length === 0) return null;
  return (
    <Block
      title="Extracted configuration"
      count={config.length}
      actions={<CopyButton value={configText(config)} what="the whole configuration" label="copy all" />}
    >
      <dl className="border-t border-border-light text-sm">
        {config.map((item) => (
          <div
            key={`${item.key}=${item.value}`}
            className="grid items-start gap-x-4 gap-y-0.5 border-b border-border-light py-2 @[36rem]:grid-cols-[minmax(8rem,14rem)_minmax(0,1fr)_auto]"
          >
            <dt className="text-text-secondary">{item.key}</dt>
            <dd className="min-w-0">
              <span className="break-all font-mono text-xs text-text-primary">{item.value}</span>
              <span className="ml-2 text-[11px] text-text-muted">{howObtained(item)}</span>
            </dd>
            <dd>
              <CopyButton value={item.value} what={`configuration value ${item.key}`} label="copy" />
            </dd>
          </div>
        ))}
      </dl>
    </Block>
  );
}

/* ── Facts rail ────────────────────────────────────────────────────── */

/** A block of the rail: a heading, its facts, and a hairline above the next. */
function Fact({ title, children, id, count }: { title: string; children: ReactNode; id?: string; count?: number }) {
  const headingId = `rail-${title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
  return (
    <section
      id={id}
      aria-labelledby={headingId}
      className="scroll-mt-16 break-inside-avoid border-b border-border-light px-4 py-4 last:border-b-0"
    >
      <h2 id={headingId} className="mb-2.5 text-sm font-semibold text-text-primary">
        {title}
        {count != null && " "}{count != null && <span className="ml-0.5 font-normal text-text-muted tabular-nums">{count}</span>}
      </h2>
      {children}
    </section>
  );
}

function ActNow({ mr }: { mr: MalwareReport }) {
  const [all, setAll] = useState(false);
  const [why, setWhy] = useState(false);
  const recs = sortedRecommendations(mr.defensive_recommendations);
  if (recs.length === 0) {
    return (
      <Fact title="Act now" id="recommendations">
        <p className="text-xs text-text-muted">The report makes no recommendation.</p>
      </Fact>
    );
  }
  const shown = all ? recs : recs.slice(0, FIRST_ACTIONS);
  const whyId = "act-now-why";
  return (
    <Fact title="Act now" id="recommendations" count={recs.length}>
      <ol className="space-y-3 text-sm">
        {shown.map((r, i) => {
          const p = PRIORITY_STYLES[r.priority];
          return (
            <li key={`${r.priority}-${r.action}`} className="flex gap-2.5">
              <span
                className={`mt-0.5 inline-flex h-5 shrink-0 items-center rounded px-1.5 text-[11px] font-semibold ${p?.text ?? "text-text-secondary"} ${p?.bg ?? "bg-bg-active"}`}
                title={p?.label}
              >
                {r.priority}
              </span>
              <div className="min-w-0 space-y-1">
                <SafeMarkdown markdown={r.action} cite inline regionName={`Action ${i + 1}`} className="text-sm leading-5 text-text-primary" />
                {why && (
                  <div id={`${whyId}-${i}`} className="space-y-1 text-xs text-text-secondary">
                    <p className="flex flex-wrap items-center gap-2 text-[11px] text-text-muted">
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
                    {r.rationale && <SafeMarkdown markdown={r.rationale} cite regionName={`Action ${i + 1} reason`} className="space-y-1" />}
                    {r.detection && <p className="text-text-muted">Detect with: {r.detection}</p>}
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ol>
      {/* One control for every step's reason, not one per step: the first
          screen stays calm and the reasons open together. */}
      <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs">
        <button
          type="button"
          aria-expanded={why}
          onClick={() => setWhy((v) => !v)}
          className="text-accent-strong hover:underline"
        >
          {why ? "Hide why and how to detect" : "Why, and how to detect"}
        </button>
        {recs.length > FIRST_ACTIONS && (
          <button type="button" onClick={() => setAll((v) => !v)} className="text-accent-strong hover:underline">
            {all ? `Show the first ${FIRST_ACTIONS}` : `Show all ${recs.length} steps`}
          </button>
        )}
      </div>
    </Fact>
  );
}

function Severity({ mr }: { mr: MalwareReport }) {
  const [open, setOpen] = useState(false);
  if (!mr.severity) return null;
  const impact = mr.severity.business_impact?.trim() ?? "";
  return (
    <Fact title="Severity">
      <SeverityPill severity={mr.severity.rating} />
      {impact && (
        <div className="mt-2">
          <div className={`text-xs leading-5 text-text-secondary ${open ? "" : "line-clamp-4"}`}>
            <SafeMarkdown markdown={impact} cite regionName="Severity" className="space-y-1" />
          </div>
          <button
            type="button"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
            className="mt-1 text-[11px] text-accent-strong hover:underline"
          >
            {open ? "Show less" : "Read why"}
          </button>
        </div>
      )}
    </Fact>
  );
}

function TopIndicators({ mr, jobId }: { mr: MalwareReport; jobId: string }) {
  const rows = indicatorRows(mr);
  if (rows.length === 0) return null;
  /* What a responder blocks first: published network values, then the other
   * published values; a value held back is listed under Indicators only, and
   * the sample's own hashes are in the header with their copy already. */
  const own = new Set(
    Object.values(mr.identity?.hashes ?? {})
      .filter(Boolean)
      .map((h) => String(h).toLowerCase()),
  );
  const published = rows.filter((r) => r.publication === "published" && !own.has(r.value.trim().toLowerCase()));
  const network = (r: (typeof rows)[number]) => /domain|fqdn|host|ip|url|uri/i.test(r.kind || r.type);
  const ordered = [...published.filter(network), ...published.filter((r) => !network(r))];
  const top = ordered.slice(0, FIRST_INDICATORS);
  return (
    <Fact title="Indicators" count={rows.length}>
      {top.length === 0 ? (
        <p className="text-xs text-text-muted">None of them is published.</p>
      ) : (
        <ul className="space-y-1.5">
          {top.map((r) => (
            <li key={`${r.type}:${r.value}`} className="flex items-center gap-2">
              <span className="w-16 shrink-0 truncate text-[11px] text-text-muted" title={r.type}>
                {r.type}
              </span>
              <code className="min-w-0 flex-1 truncate font-mono text-xs text-text-primary" title={r.value}>
                {r.value.length > 64 ? truncateMiddle(r.value, 40) : r.value}
              </code>
              <CopyButton value={r.value} what={`${r.type} ${r.value}`} label="copy" />
            </li>
          ))}
        </ul>
      )}
      <Link href={analysisHref(jobId, "indicators")} className="mt-2.5 inline-block text-xs text-accent-strong hover:underline">
        All {countLabel(rows.length, "indicator")}
      </Link>
    </Fact>
  );
}

const GROUPS: { basis: Basis; title: string }[] = [
  { basis: "seen", title: "Seen in sandbox" },
  { basis: "not-seen", title: "Not seen in sandbox" },
  { basis: "unstated", title: "Basis not stated" },
];

/* Every behaviour signature and technique, split by whether the sandbox saw
 * it; each opens its evidence. */
function Behaviours({ mr }: { mr: MalwareReport }) {
  const { showEvidence } = useReport();
  const rows = useMemo(() => findingRows(mr), [mr]);
  const [open, setOpen] = useState<Set<Basis>>(new Set());
  if (rows.length === 0) return null;
  return (
    <Fact title="Behaviour and techniques" count={rows.length}>
      <div className="space-y-4">
        {GROUPS.map(({ basis, title }) => {
          const group = rows.filter((r) => VOICE_BASIS[r.voice].basis === basis);
          if (group.length === 0) return null;
          const all = open.has(basis);
          const shown = all ? group : group.slice(0, FIRST_PER_GROUP);
          return (
            <div key={basis} role="group" aria-label={title}>
              <h3 className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-text-secondary">
                <BasisGlyph basis={basis} />
                {title}
                <span className="font-normal text-text-muted tabular-nums">{group.length}</span>
              </h3>
              <ul className="space-y-0.5">
                {shown.map((row) => (
                  <li key={row.id}>
                    <button
                      type="button"
                      onClick={(e) => openRow(showEvidence, row, e.currentTarget)}
                      title={VOICE_TEXT[row.voice]}
                      aria-label={`Show evidence: ${row.title}`}
                      className="flex w-full items-baseline gap-2 rounded px-1 py-0.5 text-left text-xs hover:bg-bg-hover"
                    >
                      <span className="min-w-0 flex-1 truncate text-text-primary">{row.title}</span>
                      {row.severity && <SeverityPill severity={row.severity} />}
                      {row.techniques[0] && row.id.startsWith("ttp-") && (
                        <span className="shrink-0 font-mono text-[11px] text-text-muted">{row.techniques[0]}</span>
                      )}
                    </button>
                  </li>
                ))}
              </ul>
              {group.length > FIRST_PER_GROUP && (
                <button
                  type="button"
                  onClick={() =>
                    setOpen((was) => {
                      const next = new Set(was);
                      if (next.has(basis)) next.delete(basis);
                      else next.add(basis);
                      return next;
                    })
                  }
                  className="mt-1 px-1 text-[11px] text-accent-strong hover:underline"
                >
                  {all ? "Show fewer" : `Show all ${group.length}`}
                </button>
              )}
            </div>
          );
        })}
      </div>
    </Fact>
  );
}

/* How much of each kind of evidence exists. A zero says "Not found" and a
 * count nobody measured "Not measured" (`kpiState`): two different answers. */
function Counts({ mr }: { mr: MalwareReport }) {
  return (
    <Fact title="Counts">
      <dl className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1 text-xs">
        {kpis(mr).map((k) => {
          const state = kpiState(k.value);
          return (
            <div key={k.key} className="contents" data-kpi={state}>
              <dt className="text-text-secondary">{k.label}</dt>
              <dd className={`text-right tabular-nums ${state === "found" ? "text-text-primary" : "text-text-muted"}`}>
                {state === "found" ? (k.value as number).toLocaleString("en-US") : state === "not-found" ? "Not found" : "Not measured"}
              </dd>
            </div>
          );
        })}
      </dl>
    </Fact>
  );
}

function FileFacts({ mr }: { mr: MalwareReport }) {
  const id = mr.identity;
  if (!id) return null;
  const facts: [string, string][] = [
    ["Kind", fileKind(id)],
    ["Size", id.file_size_bytes > 0 ? `${formatBytes(id.file_size_bytes)} (${id.file_size_bytes.toLocaleString("en-US")} bytes)` : ""],
    ["MIME type", id.mime_type ?? ""],
    ["Compiled", id.compile_timestamp ? formatDateTime(id.compile_timestamp) : ""],
    ["Signed", id.signing ? (id.signing.is_signed ? id.signing.signer_subject || "Yes" : "No") : ""],
    ["Export name", id.export_name ?? ""],
    ["Internal name", id.internal_name ?? ""],
    ["Compiler", id.language_or_compiler ?? ""],
  ];
  return (
    <Fact title="File">
      <dl className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
        {facts
          .filter(([, v]) => v)
          .map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-text-muted">{k}</dt>
              <dd className="min-w-0 break-words text-text-primary">{v}</dd>
            </div>
          ))}
      </dl>
    </Fact>
  );
}

/* Where a reader goes next outside this console: the sample's pages on the
 * services the report names and the knowledge bases it cites. An address the
 * page would not link (`referenceRows`) stays text. */
function References({ mr }: { mr: MalwareReport }) {
  const rows = referenceRows(mr);
  if (rows.length === 0) return null;
  return (
    <Fact title="References" id="references" count={rows.length}>
      <ul className="space-y-2 text-xs">
        {rows.map((row, i) => (
          <li key={`${row.source}-${i}`} className="min-w-0 space-y-0.5">
            {row.href ? (
              <a
                href={row.href}
                target="_blank"
                rel="noopener noreferrer nofollow"
                className="text-accent-strong hover:underline"
                title={row.url}
              >
                {row.source}
              </a>
            ) : (
              <span className="text-text-primary">
                {row.source}
                {row.url && <span className="ml-1 break-all text-text-muted">{row.url}</span>}
              </span>
            )}
            {row.note && <p className="break-words leading-5 text-text-secondary">{row.note}</p>}
          </li>
        ))}
      </ul>
    </Fact>
  );
}

/* How many questions were asked after the analysis finished, and the way to
 * the conversation; a new answer from the chat joins without a reload. */
function FollowUpsLine({ jobId, status }: { jobId: string; status: string | null | undefined }) {
  const { openChat } = useReport();
  const [rows, setRows] = useState<FollowUp[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const askable = canAskFollowUp(status);

  useEffect(() => {
    if (!jobId || !askable) return;
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
      if (row) setRows((held) => followUpRows([...(held ?? []).filter((r) => r.id !== row.id), row]));
    };
    window.addEventListener(FOLLOW_UP_EVENT, onAnswer);
    return () => {
      live = false;
      window.removeEventListener(FOLLOW_UP_EVENT, onAnswer);
    };
  }, [jobId, askable]);

  if (!askable) return null;
  const n = rows?.length ?? 0;
  return (
    <Fact title="Follow-up questions">
      {error && (
        <p role="alert" className="mb-1.5 text-xs text-status-red">
          {error}
        </p>
      )}
      <p className="text-xs text-text-secondary">
        {rows === null
          ? "Ask about anything in this analysis; answers come from what it stored."
          : n === 0
            ? "No question has been asked since the analysis finished."
            : `${countLabel(n, "question")} asked since the analysis finished. Latest: “${proseText(rows[n - 1].question).slice(0, 120)}”`}
      </p>
      {openChat && (
        <button type="button" onClick={(e) => openChat(e.currentTarget)} className="mt-2 text-xs text-accent-strong hover:underline">
          {n > 0 ? "Open the conversation" : "Ask a question"}
        </button>
      )}
    </Fact>
  );
}

/* ── States without a structured report ────────────────────────────── */

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
    <Block title="This analysis">
      <p className="max-w-[72ch] text-sm leading-relaxed text-text-secondary">
        This report predates the structured report payload, so it carries a verdict, a category and each
        analyst&apos;s findings and nothing more.
        {report?.malware_category ? ` The analysis called the behaviour ${report.malware_category}.` : ""}
        {agentCount > 0 ? ` ${countLabel(agentCount, "analyst")} took part; what each one concluded is ` : ""}
        {agentCount > 0 && (
          <>
            <Link href={`${analysisHref(jobId, "evidence")}/conversation`} className="text-accent-strong underline hover:no-underline">
              beside their discussion
            </Link>
            .
          </>
        )}
      </p>
    </Block>
  );
}
