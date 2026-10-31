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
 * Network: the counts first, then the hosts the run saw with what each
 * received, the HTTP, DNS and TLS tables, and the endpoints read out of the
 * sample, with reputation beside each host, and the one action that asks the
 * threat-intel services about them.
 */
export default function NetworkPage() {
  const { job } = useReport();
  return (
    <ReportGate>
      {(report) => {
        const mr = report.malware_report;
        const counts = mr ? networkCounts(mr) : null;
        const tls = (mr?.network?.ja3_fingerprints.length ?? 0) + (mr?.network?.ja3s_fingerprints.length ?? 0);
        return (
          <>
            <div className="flex flex-wrap items-start justify-between gap-3">
              {counts && (
                <section aria-label="Network counts" className="grid flex-1 grid-cols-2 gap-2 sm:grid-cols-5">
                  <KpiTile label="Domains" value={counts.domains} />
                  <KpiTile label="IPs" value={counts.ips} />
                  <KpiTile label="URLs" value={counts.urls} />
                  <KpiTile label="TLS fingerprints" value={tls} />
                  <KpiTile label="Suspicious" value={counts.suspicious} />
                </section>
              )}
              <EnrichButton reportId={report.id} />
            </div>
            {tabHasContent("/network", report, job?.roster) ? (
              <div id="network" className="scroll-mt-40">
                <NetworkContent report={report} />
              </div>
            ) : (
              <TabBlock id="network" title="Network activity" empty />
            )}
          </>
        );
      }}
    </ReportGate>
  );
}
