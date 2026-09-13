"use client";

import { Suspense } from "react";
import { useParams } from "next/navigation";
import { useReport } from "../layout";
import EvidencePanel from "@/components/analysis/EvidencePanel";
import { ArtifactSections } from "@/components/analysis/ArtifactTable";
import { unrenderedSections } from "@/components/analysis/reportSections";

/**
 * The EVIDENCE tab: the ledger the whole report is standing on.
 *
 * The panel reads `?evidence=` to open one entry, so it is a client component
 * behind a Suspense boundary — a page that calls `useSearchParams` outside one
 * is client-rendered up to the nearest boundary, and there is no reason for
 * that boundary to be the whole analysis shell.
 */
export default function EvidencePage() {
  const params = useParams();
  const { report } = useReport();
  const id = typeof params?.id === "string" ? params.id : "";
  // A section from a tool server nobody wrote this console against belongs to
  // no tab, and dropping it would undo the whole point of an open report. It
  // lands here, next to the calls it was built from — and so does a section
  // routed to a tab that does not draw sections, which is the failure this net
  // exists to catch rather than a case anyone will remember to check for.
  const unclaimed = unrenderedSections(report?.malware_report?.sections);

  return (
    <div className="p-4 space-y-4">
      <p className="text-xs text-text-secondary mb-3">
        Every tool call this run made, in the order the calls were issued. The report cites these
        ids, so a claim in it can be followed back to the call it came out of.
      </p>
      <Suspense
        fallback={<p className="text-sm text-text-secondary">Reading the ledger&hellip;</p>}
      >
        <EvidencePanel jobId={id} />
      </Suspense>
      {unclaimed.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Sections no tab draws
          </h2>
          <p className="text-[11px] text-text-muted">
            Built from this ledger by tools the typed tabs were not written against.
          </p>
          <ArtifactSections sections={unclaimed} />
        </div>
      )}
    </div>
  );
}
