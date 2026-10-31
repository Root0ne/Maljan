"use client";

import { Suspense, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useReport } from "@/components/analysis/AnalysisContext";
import EvidenceBundleView from "@/components/analysis/EvidenceBundleView";
import RunQuality from "@/components/analysis/RunQuality";
import { recordsForwardHref } from "@/components/analysis/overview";
import EvidenceRecords from "@/components/analysis/tabs/EvidenceRecords";

/**
 * The Evidence tab's first view: the run's own quality, folded, above the
 * evidence bundle once the run has a report, and above the records while it
 * has none (they fill as the run works).
 *
 * A record link written before the bundle led the tab (`?evidence=ev_0007`)
 * still lands on its record: it is passed on to Records, where the call's
 * output opens.
 */
export default function EvidencePage() {
  return (
    <div className="space-y-4">
      <RunQuality />
      <Suspense fallback={<p className="text-sm text-text-secondary">Reading the evidence&hellip;</p>}>
        <EvidenceFirstView />
      </Suspense>
    </div>
  );
}

function EvidenceFirstView() {
  const { jobId, report, loading } = useReport();
  const router = useRouter();
  const searchParams = useSearchParams();
  const query = searchParams?.toString() ?? "";
  const forward = Boolean(report && searchParams?.get("evidence"));

  useEffect(() => {
    if (forward) router.replace(recordsForwardHref(jobId, query, window.location.hash));
  }, [forward, jobId, query, router]);

  if (loading || forward) return <p className="text-sm text-text-secondary">Reading the evidence&hellip;</p>;
  if (!report) return <EvidenceRecords />;
  return <EvidenceBundleView jobId={jobId} reportId={report.id} />;
}
