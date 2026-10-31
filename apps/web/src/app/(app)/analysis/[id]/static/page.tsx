"use client";

import { useReport } from "@/components/analysis/AnalysisContext";
import ReportGate from "@/components/analysis/ReportGate";
import TabBlock from "@/components/analysis/TabBlock";
import { tabHasContent } from "@/components/analysis/analysisTabs";
import IdentityContent from "@/components/analysis/tabs/IdentityContent";
import StaticContent from "@/components/analysis/tabs/StaticContent";

/**
 * Static & code: what the file is (its identity, metadata, hashes and
 * reputation), then what reading it without running it showed: its
 * structure one part at a time, its strings, the configuration recovered
 * from it and the functions examined.
 */
export default function StaticPage() {
  const { job } = useReport();
  return (
    <ReportGate>
      {(report) => (
        <>
          {tabHasContent("/identity", report, job?.roster) ? (
            <div id="identity" className="scroll-mt-16">
              <IdentityContent />
            </div>
          ) : (
            <TabBlock id="identity" title="Identity and metadata" empty />
          )}
          {tabHasContent("/static", report, job?.roster) ? (
            <div id="static" className="scroll-mt-16">
              <StaticContent report={report} />
            </div>
          ) : (
            <TabBlock id="static" title="Static analysis" empty />
          )}
        </>
      )}
    </ReportGate>
  );
}
