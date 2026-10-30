"use client";

import { useReport } from "@/components/analysis/AnalysisContext";
import ReportGate from "@/components/analysis/ReportGate";
import TabBlock from "@/components/analysis/TabBlock";
import TechnicalAnalysisPanel from "@/components/analysis/TechnicalAnalysisPanel";
import { tabHasContent } from "@/components/analysis/analysisTabs";
import { hasTechnicalAnalysis } from "@/components/analysis/reportProse";
import AttackContent from "@/components/analysis/tabs/AttackContent";
import DynamicContent from "@/components/analysis/tabs/DynamicContent";
import PersistenceContent from "@/components/analysis/tabs/PersistenceContent";

/**
 * Behaviour: what the sample does. The technical analysis (its execution
 * flow, commands and channels), what the sandbox saw it do, the ATT&CK
 * techniques it maps to, and how it persists.
 */
export default function BehaviourPage() {
  const { job } = useReport();
  return (
    <ReportGate>
      {(report) => (
        <>
          {report.malware_report && hasTechnicalAnalysis(report.malware_report) ? (
            <div id="technical-analysis" className="scroll-mt-40">
              <TechnicalAnalysisPanel report={report.malware_report} />
            </div>
          ) : (
            <TabBlock id="technical-analysis" title="Technical analysis" empty />
          )}
          <TabBlock
            id="dynamic"
            title="Sandbox behaviour"
            empty={!tabHasContent("/dynamic", report, job?.roster)}
            emptyText="No sandbox run recorded"
          >
            <DynamicContent />
          </TabBlock>
          <TabBlock
            id="attack"
            title="ATT&CK techniques"
            empty={!tabHasContent("/capabilities", report, job?.roster)}
          >
            <AttackContent />
          </TabBlock>
          <TabBlock
            id="persistence"
            title="Persistence"
            empty={!tabHasContent("/persistence", report, job?.roster)}
          >
            <PersistenceContent />
          </TabBlock>
        </>
      )}
    </ReportGate>
  );
}
