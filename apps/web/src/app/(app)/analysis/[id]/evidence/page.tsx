"use client";

import { Suspense } from "react";
import { useParams } from "next/navigation";
import EvidencePanel from "@/components/analysis/EvidencePanel";

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
  const id = typeof params?.id === "string" ? params.id : "";

  return (
    <div className="p-4">
      <p className="text-xs text-text-secondary mb-3">
        Every tool call this run made, in the order the calls were issued. The report cites these
        ids, so a claim in it can be followed back to the call it came out of.
      </p>
      <Suspense
        fallback={<p className="text-sm text-text-secondary">Reading the ledger&hellip;</p>}
      >
        <EvidencePanel jobId={id} />
      </Suspense>
    </div>
  );
}
