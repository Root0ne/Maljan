"use client";

import { useState } from "react";

import { useReport } from "../layout";
import { api } from "@/lib/api";
import { copyToClipboard, truncateMiddle } from "@/lib/report-utils";
import type { FamilyAttribution } from "@/types/malware-report";

type SimilarSample = {
  sample_id?: string;
  malware_category?: string;
  technique_ids?: string[];
  summary?: string;
  source?: string;
  distance?: number;
};

export default function AttributionTab() {
  const { report, loading } = useReport();
  const [enrichBusy, setEnrichBusy] = useState(false);
  const [enrichMsg, setEnrichMsg] = useState<string | null>(null);

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  const attribution: FamilyAttribution | undefined =
    report?.malware_report?.attribution;
  if (!attribution) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        No attribution payload available for this report.
      </div>
    );
  }

  const reportId = report?.id;
  const triggerEnrich = async () => {
    if (!reportId || enrichBusy) return;
    setEnrichBusy(true);
    setEnrichMsg(null);
    try {
      await api.enrichReport(reportId);
      setEnrichMsg(
        "Enrichment queued. similar_samples will appear when the worker finishes.",
      );
    } catch (e) {
      setEnrichMsg(`Failed to queue enrichment: ${(e as Error).message}`);
    } finally {
      setEnrichBusy(false);
    }
  };

  const familyConfidencePct = Math.round(attribution.family_confidence * 100);
  const similars = (attribution.similar_samples as SimilarSample[]) ?? [];

  return (
    <div className="space-y-4">
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Family Attribution
          </h2>
        </div>
        <div className="p-4 grid grid-cols-3 gap-4">
          <Field
            label="Family"
            value={attribution.family || "(unattributed)"}
          />
          <Field
            label="Family Confidence"
            value={
              attribution.family
                ? `${familyConfidencePct}%`
                : "-"
            }
          />
          <Field label="Actor" value={attribution.actor || "(unknown)"} />
          <Field label="Campaign" value={attribution.campaign || "(unknown)"} />
        </div>
      </div>

      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3 flex-wrap">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Similar Samples ({similars.length})
          </h2>
          <button
            onClick={triggerEnrich}
            disabled={enrichBusy || !reportId}
            className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {enrichBusy ? "queueing..." : "trigger LTM lookup"}
          </button>
        </div>
        {enrichMsg && (
          <div className="px-4 py-2 text-xs text-text-secondary bg-bg-active border-b border-border">
            {enrichMsg}
          </div>
        )}
        {similars.length === 0 ? (
          <div className="p-8 text-center text-sm text-text-muted">
            No nearest-neighbour cases recorded yet. Run the threat-intel
            enrichment step (button above) to populate this list from the
            Maljan LTM (Qdrant).
          </div>
        ) : (
          <div className="divide-y divide-border-light">
            {similars.map((s, i) => (
              <SimilarSampleCard key={`${s.sample_id ?? "row"}-${i}`} sample={s} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-[10px] text-text-muted uppercase tracking-wider mb-1">
        {label}
      </div>
      <div className="text-sm text-text-primary break-all">{value}</div>
    </div>
  );
}

function SimilarSampleCard({ sample }: { sample: SimilarSample }) {
  const [copied, setCopied] = useState(false);
  const sampleId = sample.sample_id || "(unknown)";
  return (
    <div className="p-4">
      <div className="flex items-start gap-3 flex-wrap">
        <div className="flex items-center gap-2 min-w-0">
          <code
            className="text-xs font-mono text-status-blue"
            title={sampleId}
          >
            {truncateMiddle(sampleId, 28)}
          </code>
          {sample.sample_id && (
            <button
              onClick={async () => {
                if (await copyToClipboard(sample.sample_id!)) {
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1500);
                }
              }}
              className="text-[10px] px-1.5 py-0.5 border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted transition-colors"
            >
              {copied ? "copied" : "copy"}
            </button>
          )}
          {sample.malware_category && (
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-bg-active text-text-secondary">
              {sample.malware_category}
            </span>
          )}
          {sample.source && (
            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-status-blue/10 text-status-blue">
              {sample.source}
            </span>
          )}
          {typeof sample.distance === "number" && (
            <span className="text-[10px] font-mono text-text-muted">
              d={sample.distance.toFixed(3)}
            </span>
          )}
        </div>
      </div>
      {sample.technique_ids && sample.technique_ids.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {sample.technique_ids.slice(0, 12).map((tid) => (
            <span
              key={tid}
              className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-status-blue/10 text-status-blue"
            >
              {tid}
            </span>
          ))}
        </div>
      )}
      {sample.summary && (
        <p className="mt-2 text-xs text-text-secondary leading-relaxed">
          {sample.summary}
        </p>
      )}
    </div>
  );
}
