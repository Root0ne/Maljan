"use client";

import Link from "next/link";
import { useParams } from "next/navigation";

/**
 * The ledger entries a section or a finding was built from, as links.
 *
 * A citation is only worth printing if a reader can follow it, so an id is
 * never rendered as bare text here: each chip is a link to the evidence panel
 * with the entry's own deep link, which opens the row and scrolls to it. The
 * job id comes from the route rather than a prop because every caller is
 * already inside `analysis/[id]`, and threading it through four levels of
 * report rendering bought nothing.
 */
export default function EvidenceChips({
  ids,
  source,
  className = "",
}: {
  ids: string[] | null | undefined;
  /** Where the section came from when it cites no entry — `tool`, `routing`,
   *  `agent` or `agent:<name>`. Printed as a plain chip: it is a provenance
   *  claim, not a citation, and nothing resolves it. */
  source?: string;
  className?: string;
}) {
  const params = useParams();
  const jobId = typeof params?.id === "string" ? params.id : "";
  const entries = (ids ?? []).filter((id) => typeof id === "string" && id.length > 0);

  if (entries.length === 0 && !source) return null;

  return (
    <span className={`inline-flex flex-wrap items-center gap-1 ${className}`}>
      {entries.map((id) => (
        <Link
          key={id}
          href={`/analysis/${jobId}/evidence?evidence=${encodeURIComponent(id)}`}
          className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-accent/15 text-accent-strong hover:bg-accent/25 transition-colors"
          title="Open this call in the evidence ledger"
        >
          {id}
        </Link>
      ))}
      {entries.length === 0 && source && (
        <span
          className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-bg-active text-text-muted"
          title="No ledger entry; this is the finding the section came from"
        >
          {source}
        </span>
      )}
    </span>
  );
}
