"use client";

import { useReport } from "@/components/analysis/AnalysisContext";
import ReportGate from "@/components/analysis/ReportGate";
import TabBlock from "@/components/analysis/TabBlock";
import { tabHasContent } from "@/components/analysis/analysisTabs";
import AttributionContent from "@/components/analysis/tabs/AttributionContent";
import DetectionContent from "@/components/analysis/tabs/DetectionContent";

/**
 * Indicators & detection: the rules that fired, the rules the analysis
 * wrote, every indicator with whether it is published and why, the STIX
 * bundle as a graph or table, and what the sample was attributed to. Every
 * file of it downloads from the Export menu.
 */
export default function IndicatorsPage() {
  const { job } = useReport();
  return (
    <ReportGate>
      {(report) => (
        <>
          <TabBlock
            id="detection"
            title="Detection and indicators"
            empty={!tabHasContent("/detection", report, job?.roster)}
            emptyText="No rule fired and none was written"
          >
            <DetectionContent />
          </TabBlock>
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
