"use client";

/* What a reputation service said about this file.
 *
 * The section is named after the service that answered — "VirusTotal" when the
 * ledger holds a `get_file_report`, "Threat intelligence" when it holds a
 * `check_hash` — because "reputation" alone hides which of the two the run
 * actually asked, and the two answer differently. A run that asked nobody
 * draws nothing: a key in the settings is not a finding.
 *
 * It sits beside the hashes, which is what was looked up.
 */

import { useEffect, useState } from "react";
import Link from "next/link";

import { api } from "@/lib/api";
import {
  REPUTATION_TOOLS,
  reputationFromLedger,
  type Reputation,
} from "./reputation";

/** The reputation answer this job's ledger holds, if it holds one. */
function useReputation(jobId: string, enabled: boolean): Reputation | null {
  const [reputation, setReputation] = useState<Reputation | null>(null);

  useEffect(() => {
    if (!jobId || !enabled) return;
    let cancelled = false;

    (async () => {
      // At most one of the two tools is ever configured, so the second request
      // is only made when the first found nothing — which is also the case
      // where it costs nothing, the ledger having no reputation row at all.
      for (const tool of REPUTATION_TOOLS) {
        try {
          const page = await api.getJobEvidence(jobId, { tool, pageSize: 5 });
          if (cancelled) return;
          const found = reputationFromLedger(page.entries);
          if (found) {
            setReputation(found);
            return;
          }
        } catch {
          // A ledger the browser could not read is not a sample with no
          // reputation. Nothing is drawn either way, and the EVIDENCE tab is
          // where a failure to read the ledger is reported.
          if (cancelled) return;
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [jobId, enabled]);

  return reputation;
}

function day(iso: string | null): string {
  if (!iso) return "";
  const at = new Date(iso);
  return Number.isNaN(at.getTime()) ? "" : at.toISOString().slice(0, 10);
}

export default function ReputationSection({
  jobId,
  enabled = true,
}: {
  jobId: string;
  /** False while the report is still loading, so nothing is asked too early. */
  enabled?: boolean;
}) {
  const reputation = useReputation(jobId, enabled);
  if (!reputation) return null;

  const { engines, malicious, suspicious, labels, firstSeen, lastSeen, link } = reputation;
  const detectionClass =
    malicious === null
      ? "text-text-primary"
      : malicious > 0
        ? "text-status-red"
        : "text-status-green";

  return (
    <div className="bg-bg-surface border border-border rounded" data-testid="reputation-section">
      <div className="px-4 py-3 border-b border-border flex items-center gap-3 flex-wrap">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          {reputation.service}
        </h2>
        <Link
          href={`/analysis/${jobId}/evidence?evidence=${encodeURIComponent(reputation.entryId)}`}
          className="text-[11px] font-mono text-accent-strong hover:underline"
        >
          {reputation.entryId}
        </Link>
        {link && (
          <a
            href={link}
            target="_blank"
            rel="noreferrer noopener"
            className="ml-auto text-[11px] text-accent-strong hover:underline"
          >
            Open the full report
          </a>
        )}
      </div>

      <div className="p-4 space-y-3">
        {engines !== null ? (
          <div className="flex flex-wrap items-baseline gap-x-6 gap-y-2">
            <div>
              <div className="text-[11px] text-text-muted uppercase tracking-wider">
                Detections
              </div>
              <div className={`text-2xl font-mono ${detectionClass}`}>
                {malicious ?? 0}
                <span className="text-sm text-text-muted">/{engines}</span>
              </div>
            </div>
            {suspicious !== null && suspicious > 0 && (
              <div>
                <div className="text-[11px] text-text-muted uppercase tracking-wider">
                  Suspicious
                </div>
                <div className="text-2xl font-mono text-status-orange">{suspicious}</div>
              </div>
            )}
            {day(firstSeen) && (
              <div>
                <div className="text-[11px] text-text-muted uppercase tracking-wider">
                  First seen
                </div>
                <div className="text-sm font-mono text-text-secondary">{day(firstSeen)}</div>
              </div>
            )}
            {day(lastSeen) && (
              <div>
                <div className="text-[11px] text-text-muted uppercase tracking-wider">
                  Last seen
                </div>
                <div className="text-sm font-mono text-text-secondary">{day(lastSeen)}</div>
              </div>
            )}
          </div>
        ) : (
          <p className="text-sm text-text-secondary leading-relaxed">{reputation.summary}</p>
        )}

        {labels.length > 0 && (
          <div>
            <div className="text-[11px] text-text-muted uppercase tracking-wider mb-1.5">
              Labels
            </div>
            <div className="flex flex-wrap gap-1.5">
              {labels.map((label) => (
                <span
                  key={label}
                  className="text-[11px] px-1.5 py-0.5 rounded bg-bg-active text-text-secondary font-mono"
                >
                  {label}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
