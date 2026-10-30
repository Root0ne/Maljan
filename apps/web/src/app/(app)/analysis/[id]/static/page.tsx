"use client";

import { useReport } from "@/components/analysis/AnalysisContext";
import ReportGate from "@/components/analysis/ReportGate";
import TabBlock from "@/components/analysis/TabBlock";
import { tabHasContent } from "@/components/analysis/analysisTabs";
import IdentityContent from "@/components/analysis/tabs/IdentityContent";
import StaticContent from "@/components/analysis/tabs/StaticContent";

/**
 * Static & code: what the file is (its identity, hashes, signature and
 * reputation), then what reading it without running it showed: its
 * structure, imports, strings and the functions examined.
 */
export default function StaticPage() {
  const { job } = useReport();
  return (
    <ReportGate>
      {(report) => (
        <>
          <TabBlock id="identity" title="File identity" empty={!tabHasContent("/identity", report, job?.roster)}>
            <IdentityContent />
          </TabBlock>
          <TabBlock id="static" title="Static analysis" empty={!tabHasContent("/static", report, job?.roster)}>
            <StaticContent />
          </TabBlock>
        </>
      )}
    </ReportGate>
  );
}
