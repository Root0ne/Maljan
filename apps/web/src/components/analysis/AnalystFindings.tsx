"use client";

import { useId } from "react";

import { retryAddedLabel } from "@/lib/conversation";
import { rosterNames } from "@/lib/rosterNames";
import { useReport } from "./AnalysisContext";
import ConfidenceMeter from "./ConfidenceMeter";
import type { AnalystClaims } from "./dynamicClaims";
import { CitedRecords } from "./EvidenceChips";
import { verdictConfidence } from "./overview";
import SafeMarkdown from "./SafeMarkdown";

/**
 * What each analyst concluded, claim by claim, with its confidence and the
 * records it cites.
 *
 * One level, not a card: it sits inside a tab's block, so it is a heading,
 * each analyst's name as a small heading under it, and the claims as rows
 * divided by hairlines, the way Overview lists its findings. A claim's
 * confidence is the same quiet five-step meter the header uses, and each
 * record it cites is one chip.
 */
export default function AnalystFindings({ findings }: { findings: AnalystClaims[] }) {
  const { job } = useReport();
  const headingId = useId();
  const names = rosterNames(job?.roster, (key) => key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, " "));
  return (
    <section aria-labelledby={headingId} className="space-y-4">
      <h3 id={headingId} className="text-sm font-semibold text-text-primary">
        Analyst findings
      </h3>
      {findings.map((f) => (
        <div key={f.agent} className="space-y-1">
          <h4 className="text-xs font-medium text-text-secondary">{names.agent(f.agent)}</h4>
          <ul className="border-t border-border-light">
            {f.claims.map((c, i) => {
              const evidence = Array.isArray(c.evidence_ref) ? c.evidence_ref.join(", ") : c.evidence_ref;
              const confidence =
                typeof c.confidence === "number" ? verdictConfidence("", c.confidence) : null;
              return (
                <li key={i} className="space-y-1.5 border-b border-border-light py-3">
                  <SafeMarkdown
                    markdown={c.claim || c.description || "(no text)"}
                    cite
                    regionName={`${names.agent(f.agent)} claim ${i + 1}`}
                    className="max-w-[80ch] space-y-2 text-sm leading-relaxed text-text-primary"
                  />
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-text-secondary">
                    {confidence && confidence.percent !== null && (
                      <span className="inline-flex items-center gap-1.5">
                        <ConfidenceMeter
                          confidence={{ ...confidence, label: `Claim confidence ${confidence.percent} percent` }}
                          compact
                          title="How sure the analyst is of this claim"
                        />
                        <span className="tabular-nums">{confidence.percent}% confidence</span>
                      </span>
                    )}
                    {Number.isInteger(c.added_by_retry_in_round) && (
                      <span>{retryAddedLabel(Number(c.added_by_retry_in_round))}</span>
                    )}
                    {evidence && (
                      <span className="inline-flex min-w-0 flex-wrap items-center gap-1.5 [overflow-wrap:anywhere]">
                        <span className="text-text-muted">Evidence</span>
                        {/* An analyst's reference is prose naming ids
                            ("ev_0004, ev_0020 (encoded blobs)"): each record
                            is one chip with its words, never bare brackets. */}
                        <CitedRecords text={evidence} />
                      </span>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </section>
  );
}
