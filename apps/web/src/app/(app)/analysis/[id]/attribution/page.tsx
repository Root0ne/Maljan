"use client";

import { useState } from "react";

import { useReport } from "../layout";
import { copyToClipboard, truncateMiddle } from "@/lib/report-utils";
import Field from "@/components/ui/Field";
import { attributionSaysSomething } from "@/components/analysis/analysisTabs";
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

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  const attribution: FamilyAttribution | undefined =
    report?.malware_report?.attribution;
  /* The same rule the tab bar applies: the block is on every report, so its
   * presence says nothing — what it named does. A direct link to this tab on
   * a run that named nothing gets the sentence written for it rather than a
   * card of "(unknown)"s. */
  if (!attribution || !attributionSaysSomething(report?.malware_report ?? null)) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        This run named no family, actor or campaign.
      </div>
    );
  }

  const familyConfidencePct = Math.round(attribution.family_confidence * 100);
  const malwareCategory = report?.malware_report?.malware_category;
  const similars = (attribution.similar_samples as SimilarSample[]) ?? [];
  // Absent on every report written before these fields existed, hence the fallbacks.
  const hashMatches = attribution.function_hash_matches ?? [];
  const ragCandidates = attribution.family_rag_candidates ?? [];
  // An ungrounded family is one the judge named without citing the evidence
  // ids it read the name from. It is kept — a flagged attribution is more
  // useful than a deleted one — and rendered muted + struck through +
  // "(unverified)" so nobody mistakes it for a corroborated identification.
  const familyUngrounded =
    !!attribution.family && attribution.family_grounded === false;
  const familyDisplay = attribution.family
    ? familyUngrounded
      ? `${attribution.family} (unverified)`
      : attribution.family
    : "(unattributed)";
  const familyValueClass = familyUngrounded
    ? "text-text-muted line-through"
    : "";

  return (
    <div className="space-y-4">
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Family Attribution
          </h2>
        </div>
        <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          <Field
            label="Family"
            value={familyDisplay}
            valueClassName={familyValueClass}
          />
          <Field
            label="Category"
            value={
              malwareCategory
                ? `${malwareCategory} (behavioural class)`
                : "(unclassified)"
            }
          />
          <Field
            label="Family Confidence"
            value={
              attribution.family && !familyUngrounded
                ? `${familyConfidencePct}%`
                : "-"
            }
          />
          <Field label="Actor" value={attribution.actor || "(unknown)"} />
          <Field label="Campaign" value={attribution.campaign || "(unknown)"} />
        </div>
        {!attribution.family && (
          <div className="px-4 pb-3 -mt-2 text-[11px] text-text-muted">
            No specific malware family was attributed. The behavioural{" "}
            <span className="text-text-secondary">category</span> above
            classifies how the sample behaves — it is not a family name.
          </div>
        )}
        {familyUngrounded && (
          <div className="px-4 pb-3 -mt-2 text-[11px] text-text-muted">
            Family was emitted by the verdict LLM but is not corroborated by
            sandbox CTI, sandbox signatures, or analyst claims. Treat as
            unverified.
          </div>
        )}
      </div>

      {hashMatches.length > 0 && (
        <EvidenceTable
          title={`Function-Hash Matches (${hashMatches.length})`}
          note="Exact normalized-opcode hashes shared with previously analysed samples. The strongest of the four evidence sources here: this is code reuse, not resemblance."
          headers={["Family", "Conf.", "Shared fns", "Example functions"]}
          columnClass={["text-text-primary", "font-mono", "font-mono", ""]}
          rows={hashMatches.map((m, i) => ({
            key: `${m.family}-${i}`,
            cells: [
              m.family,
              fmt(m.confidence, 2),
              m.shared_functions ?? "-",
              <Markers key="fns" items={(m.example_functions ?? []).slice(0, 4)} />,
            ],
          }))}
        />
      )}

      {ragCandidates.length > 0 && (
        <EvidenceTable
          title={`Family-Feature RAG Candidates (${ragCandidates.length})`}
          note="Families retrieved by static-feature similarity to a reference fingerprint catalog. Retrieval, not proof — shown because the verdict LLM weighed it."
          headers={["Family", "Similarity", "Category", "Samples"]}
          columnClass={["text-text-primary", "font-mono", "", "font-mono"]}
          rows={ragCandidates.map((c, i) => ({
            key: `${c.family}-${i}`,
            cells: [
              c.family,
              fmt(c.similarity, 3),
              c.malware_category || "-",
              c.sample_count ?? "-",
            ],
          }))}
        />
      )}

      {/* The nearest-neighbour cases, when the run found some. The button that
        * fills this list is the run's one enrichment action, on SUMMARY —
        * there was a copy of it here and another on NETWORK, both queueing the
        * same endpoint. */}
      {similars.length > 0 && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
              Similar Samples ({similars.length})
            </h2>
          </div>
          <div className="divide-y divide-border-light">
            {similars.map((s, i) => (
              <SimilarSampleCard key={`${s.sample_id ?? "row"}-${i}`} sample={s} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function fmt(value: number | null | undefined, digits: number): string {
  return typeof value === "number" ? value.toFixed(digits) : "-";
}

function Markers({ items }: { items: string[] }) {
  if (items.length === 0) return <span className="text-text-muted">-</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((item) => (
        <code
          key={item}
          className="px-1.5 py-0.5 rounded bg-bg-active font-mono text-[11px] text-status-blue"
        >
          {item}
        </code>
      ))}
    </div>
  );
}

/** Three of the four attribution evidence sources render the same shape, so
 *  they share one component rather than three near-identical tables. The
 *  offensive-tool table stays hand-rolled: its Markers column and its
 *  sandbox-independence note make it the odd one out. */
function EvidenceTable({
  title,
  note,
  headers,
  columnClass,
  rows,
}: {
  title: string;
  note: string;
  headers: string[];
  /** Per-column cell classes. Styling lives here rather than in the cell
   *  values so callers can pass plain strings and numbers — an array of bare
   *  JSX spans would need a key on every one of them. */
  columnClass?: string[];
  rows: { key: string; cells: React.ReactNode[] }[];
}) {
  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          {title}
        </h2>
        <p className="mt-1 text-[11px] text-text-muted">{note}</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-text-muted border-b border-border-light">
              {headers.map((h) => (
                <th key={h} scope="col" className="px-4 py-2 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border-light">
            {rows.map((row) => (
              <tr key={row.key}>
                {row.cells.map((cell, i) => (
                  <td
                    key={`${row.key}-${headers[i]}`}
                    className={`px-4 py-2 text-text-secondary ${columnClass?.[i] ?? ""}`}
                  >
                    {cell}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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
              className="text-[11px] px-1.5 py-0.5 border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted"
            >
              {copied ? "copied" : "copy"}
            </button>
          )}
          {sample.malware_category && (
            <span className="text-[11px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-bg-active text-text-secondary">
              {sample.malware_category}
            </span>
          )}
          {sample.source && (
            <span className="text-[11px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-status-blue/10 text-status-blue">
              {sample.source}
            </span>
          )}
          {typeof sample.distance === "number" && (
            <span className="text-[11px] font-mono text-text-muted">
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
              className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-status-blue/10 text-status-blue"
            >
              {tid}
            </span>
          ))}
        </div>
      )}
      {sample.summary && (
        <p className="mt-2 text-sm text-text-secondary leading-relaxed">
          {sample.summary}
        </p>
      )}
    </div>
  );
}
