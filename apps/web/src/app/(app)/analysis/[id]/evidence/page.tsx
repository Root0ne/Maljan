"use client";

import RunQuality from "@/components/analysis/RunQuality";
import EvidenceRecords from "@/components/analysis/tabs/EvidenceRecords";

/** The records behind the report, with the run's own quality folded above them. */
export default function EvidencePage() {
  return (
    <div className="space-y-4">
      <RunQuality />
      <EvidenceRecords />
    </div>
  );
}
