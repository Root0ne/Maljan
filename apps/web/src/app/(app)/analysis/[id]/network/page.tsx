"use client";

import { useReport } from "@/components/analysis/AnalysisContext";
import EnrichButton from "@/components/analysis/EnrichButton";
import ReportGate from "@/components/analysis/ReportGate";
import TabBlock from "@/components/analysis/TabBlock";
import { tabHasContent } from "@/components/analysis/analysisTabs";
import { networkCounts } from "@/components/analysis/networkFacts";
import NetworkContent from "@/components/analysis/tabs/NetworkContent";
import KpiTile from "@/components/ui/KpiTile";

/**
 * Network: the counts first, then every endpoint the run saw or read out of
 * the sample, with reputation beside each, and the one action that asks the
 * threat-intel services about them.
 */
export default function NetworkPage() {
  const { job } = useReport();
  return (
    <ReportGate>
      {(report) => {
        const mr = report.malware_report;
        const counts = mr ? networkCounts(mr) : null;
        return (
          <>
            <div className="flex flex-wrap items-start justify-between gap-3">
              {counts && (
                <section aria-label="Network counts" className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-4">
                  <KpiTile label="Domains" value={counts.domains} />
                  <KpiTile label="IPs" value={counts.ips} />
                  <KpiTile label="URLs" value={counts.urls} />
                  <KpiTile label="Suspicious" value={counts.suspicious} />
                </section>
              )}
              <EnrichButton reportId={report.id} />
            </div>
            <TabBlock
              id="network"
              title="Network activity"
              empty={!tabHasContent("/network", report, job?.roster)}
            >
              <NetworkContent />
            </TabBlock>
          </>
        );
      }}
    </ReportGate>
  );
}
