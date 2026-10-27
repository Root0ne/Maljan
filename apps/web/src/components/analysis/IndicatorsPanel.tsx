"use client";

import Th from "@/components/ui/Th";
import type { MalwareReport } from "@/types/malware-report";
import { CitedText } from "./EvidenceChips";
import { indicatorRows, judgeIndicatorRows, type Decision } from "./indicators";

/**
 * Every indicator the report holds, each with whether the export publishes it
 * and the rule's reason (`indicators.ts`), then the judge's own indicators
 * beside the decision the table records for each.
 */
export default function IndicatorsPanel({ mr }: { mr: MalwareReport | null | undefined }) {
  const rows = indicatorRows(mr);
  const judged = judgeIndicatorRows(mr);
  if (rows.length === 0 && judged.length === 0) return null;
  const published = rows.filter((row) => row.publication === "published").length;

  return (
    <div className="space-y-4" data-testid="indicators-panel">
      {rows.length > 0 && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border flex flex-wrap items-baseline gap-2">
            <h3 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Indicators ({rows.length})
            </h3>
            <span className="text-[11px] text-text-muted">
              {published} published · {rows.length - published} withheld
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <Th>Type</Th>
                  <Th>Value</Th>
                  <Th>Source</Th>
                  <Th>Export</Th>
                  <Th>Reason</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-light">
                {rows.map((row, i) => (
                  <tr key={`${row.type}-${row.value}-${i}`} className="hover:bg-bg-hover align-top">
                    <td className="px-4 py-2 text-[11px] uppercase tracking-wider text-text-muted whitespace-nowrap">
                      {row.type || "-"}
                    </td>
                    <td className="px-4 py-2">
                      <code className="text-xs font-mono text-status-blue break-all">{row.value}</code>
                      {row.context && (
                        <div className="text-[11px] text-text-muted mt-0.5 break-words">
                          {row.context}
                        </div>
                      )}
                      {row.recoveredBy && (
                        <div className="text-[11px] text-text-muted mt-0.5 break-words">
                          <span className="text-text-secondary">Recovered by: </span>
                          <CitedText text={row.recoveredBy} />
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs text-text-secondary whitespace-nowrap">
                      {row.source || "-"}
                    </td>
                    <td className="px-4 py-2">
                      <PublicationBadge decision={row} />
                    </td>
                    <td className="px-4 py-2 text-xs text-text-secondary break-words">
                      <Reason decision={row} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {judged.length > 0 && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h3 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Judge&apos;s indicators ({judged.length})
            </h3>
            <p className="mt-1 text-[11px] text-text-muted">
              The values the judge&apos;s own STIX patterns name, each with the decision the
              indicator table records for the same value.
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <Th>Kind</Th>
                  <Th>Value</Th>
                  <Th>Algorithm</Th>
                  <Th>Export</Th>
                  <Th>Reason</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-light">
                {judged.map((ind, i) => (
                  <tr key={`${ind.kind}-${ind.value}-${i}`} className="hover:bg-bg-hover align-top">
                    <td className="px-4 py-2 text-[11px] uppercase tracking-wider text-text-muted whitespace-nowrap">
                      {ind.kind || "-"}
                    </td>
                    <td className="px-4 py-2">
                      <code className="text-xs font-mono text-status-blue break-all">{ind.value}</code>
                    </td>
                    <td className="px-4 py-2 text-xs font-mono text-text-secondary">
                      {ind.algorithm || "-"}
                    </td>
                    <td className="px-4 py-2">
                      {ind.decision ? (
                        <PublicationBadge decision={ind.decision} />
                      ) : (
                        <span className="text-[11px] italic text-text-muted">
                          not in the indicator table
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs text-text-secondary break-words">
                      {ind.decision ? <Reason decision={ind.decision} /> : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

function PublicationBadge({ decision }: { decision: Decision }) {
  const published = decision.publication === "published";
  return (
    <span
      className={`text-[11px] uppercase tracking-wider px-1.5 py-0.5 rounded whitespace-nowrap ${
        published ? "bg-status-green/10 text-status-green" : "bg-bg-active text-text-muted"
      }`}
      title={
        published
          ? "Exported in the STIX bundle"
          : "Held out of the STIX bundle by the publish rule"
      }
    >
      {published ? "published" : "withheld"}
    </span>
  );
}

function Reason({ decision }: { decision: Decision }) {
  if (!decision.answered) {
    return (
      <span className="italic text-text-muted">the publish rule recorded no answer</span>
    );
  }
  if (!decision.reason) return <span className="text-text-muted">-</span>;
  return <CitedText text={decision.reason} />;
}
