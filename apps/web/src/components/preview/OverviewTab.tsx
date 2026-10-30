"use client";

import { useState } from "react";
import { ChevronRight } from "lucide-react";
import CopyButton from "@/components/ui/CopyButton";
import KpiTile from "@/components/ui/KpiTile";
import Section from "@/components/ui/Section";
import { SeverityPill } from "@/components/ui/Pill";
import { PRIORITY_STYLES } from "@/types/malware-report";
import CitedProse from "./CitedProse";
import { usePreview } from "./PreviewFrame";
import {
  PREVIEW_TABS,
  VOICE_TEXT,
  configText,
  findingRows,
  howObtained,
  kpis,
  previewHref,
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
 * where none does), the findings table highest severity first with a caret
 * that opens the evidence behind a row, the configuration the analysis
 * extracted, and what to do about it.
 */

const FIRST_ROWS = 10;
const MAX_KEY_FINDINGS = 8;

export default function OverviewTab() {
  const { jobId, report, showEvidence } = usePreview();
  const [allRows, setAllRows] = useState(false);
  const mr = report?.malware_report ?? null;

  if (!report || !mr) {
    return (
      <p className="text-sm text-text-secondary">
        This analysis stored no report, so there is nothing to summarise.
      </p>
    );
  }

  const keyFindings = (mr.key_findings ?? []).slice(0, MAX_KEY_FINDINGS);
  const rows = findingRows(mr);
  const visible = allRows ? rows : rows.slice(0, FIRST_ROWS);
  const config = mr.technical_analysis?.configuration ?? [];
  const recs = sortedRecommendations(mr.defensive_recommendations);
  const tabHref = (key: string) => {
    const tab = PREVIEW_TABS.find((t) => t.key === key);
    return tab ? previewHref(jobId, tab) : undefined;
  };

  const openRow = (row: FindingRow, opener: HTMLElement) =>
    showEvidence(
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
      <Section title="Summary" empty={!mr.executive_summary && keyFindings.length === 0}>
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
          {mr.executive_summary && (
            <p className="text-sm leading-6 text-text-primary">
              <CitedProse text={mr.executive_summary} />
            </p>
          )}
          {keyFindings.length > 0 && (
            <ul className="list-disc space-y-1 pl-5 text-sm leading-6 text-text-primary">
              {keyFindings.map((f, i) => (
                <li key={f.text}>
                  <CitedProse text={f.text} />
                  {f.evidence_ids.length > 0 && (
                    <sup className="ml-0.5">
                      <button
                        type="button"
                        onClick={(e) =>
                          showEvidence(
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
        </div>
      </Section>

      <section aria-label="Counts">
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
          {kpis(mr).map((k) => (
            <KpiTile key={k.key} label={k.label} value={k.value} href={tabHref(k.tab)} />
          ))}
        </div>
      </section>

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
  );
}
