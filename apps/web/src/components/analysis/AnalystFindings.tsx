"use client";

import { confidenceClass } from "@/lib/report-utils";
import type { AnalystClaims } from "./dynamicClaims";
import { CitedText } from "./EvidenceChips";

/** What each analyst concluded, claim by claim, with its confidence and evidence. */
export default function AnalystFindings({
  findings,
}: {
  findings: AnalystClaims[];
}) {
  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          Analyst findings
        </h2>
      </div>
      <div className="p-4 space-y-3">
        {findings.map((f) => (
          <div key={f.agent}>
            <p className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
              {f.agent}
            </p>
            <ul className="space-y-2">
              {f.claims.map((c, i) => {
                const conf =
                  typeof c.confidence === "number"
                    ? Math.round(c.confidence * 100)
                    : null;
                const evidence = Array.isArray(c.evidence_ref)
                  ? c.evidence_ref.join(", ")
                  : c.evidence_ref;
                return (
                  <li
                    key={i}
                    className="border border-border-light rounded p-3"
                  >
                    <p className="text-sm text-text-primary leading-relaxed">
                      {c.claim || c.description || "(no text)"}
                    </p>
                    <div className="flex flex-wrap gap-3 mt-1.5 text-[11px] text-text-muted">
                      {conf !== null && (
                        <span className={`font-mono ${confidenceClass(conf)}`}>
                          {conf}%
                        </span>
                      )}
                      {evidence && (
                        <span>
                          <span className="text-text-secondary">
                            Evidence:{" "}
                          </span>
                          {/* An analyst's reference is prose naming ids
                              ("ev_0004, ev_0020 (encoded blobs)"): each id
                              opens its entry, the words stay words. */}
                          <CitedText text={evidence} />
                        </span>
                      )}
                    </div>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
