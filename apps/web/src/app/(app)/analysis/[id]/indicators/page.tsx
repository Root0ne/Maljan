"use client";

import { useReport } from "@/components/analysis/AnalysisContext";
import ReportGate from "@/components/analysis/ReportGate";
import TabBlock from "@/components/analysis/TabBlock";
import { tabHasContent } from "@/components/analysis/analysisTabs";
import AttributionContent from "@/components/analysis/tabs/AttributionContent";
import DetectionContent from "@/components/analysis/tabs/DetectionContent";

/**
 * Indicators & detection: every indicator with whether it is published and
 * why, the rules that fired, the rules the analysis wrote, the STIX bundle on
 * request, and what the sample was attributed to. Every file of it downloads
 * from the Export menu.
 */
export default function IndicatorsPage() {
  const { job } = useReport();
  return (
    <ReportGate>
      {(report) => (
        <>
          {tabHasContent("/detection", report, job?.roster) ? (
            <div id="detection" className="scroll-mt-16">
              <DetectionContent />
            </div>
          ) : (
            <TabBlock
              id="detection"
              title="Detection and indicators"
              empty
              emptyText="No rule fired and none was written"
            />
          )}
          <TabBlock
            id="attribution"
            title="Attribution"
            empty={!tabHasContent("/attribution", report, job?.roster)}
          >
            <AttributionContent />
          </TabBlock>
        </>
      )}
    </ReportGate>
  );
}
