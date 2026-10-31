"use client";

import { useEffect, useState } from "react";

import { useReport } from "@/components/analysis/AnalysisContext";
import ReportGate from "@/components/analysis/ReportGate";
import TabBlock from "@/components/analysis/TabBlock";
import TechnicalAnalysisPanel from "@/components/analysis/TechnicalAnalysisPanel";
import { tabHasContent } from "@/components/analysis/analysisTabs";
import { hasTechnicalAnalysis } from "@/components/analysis/reportProse";
import { sectionsForTab } from "@/components/analysis/reportSections";
import {
  techniqueTactics,
  viewKeeps,
  viewOfHash,
  type BehaviourView,
} from "@/components/analysis/behaviourView";
import AttackContent from "@/components/analysis/tabs/AttackContent";
import { BehavioursBlock, ProcessesBlock } from "@/components/analysis/tabs/DynamicContent";
import type { ReportDetailDTO } from "@/lib/api";

const VIEWS: { key: BehaviourView; label: string }[] = [
  { key: "all", label: "All behaviour" },
  { key: "persistence", label: "Persistence" },
  { key: "defence-evasion", label: "Defence evasion" },
];

/**
 * Behaviour: what the sample does. The process tree with the sample's path
 * open, its behaviours by severity and technique, the ATT&CK techniques it
 * maps to, and the technical analysis's account of its execution.
 * Persistence and defence evasion are views of the tab rather than blocks of
 * their own; `#persistence`, where the old persistence route lands, opens the
 * persistence view.
 */
export default function BehaviourPage() {
  return <ReportGate>{(report) => <BehaviourTab report={report} />}</ReportGate>;
}

function BehaviourTab({ report }: { report: ReportDetailDTO }) {
  const { job } = useReport();
  const [view, setView] = useState<BehaviourView>("all");

  useEffect(() => {
    const read = () => {
      const asked = viewOfHash(window.location.hash);
      if (asked) setView(asked);
    };
    read();
    window.addEventListener("hashchange", read);
    return () => window.removeEventListener("hashchange", read);
  }, []);

  const mr = report.malware_report;
  const tactics = techniqueTactics(mr, report.mitre_techniques);
  const persistenceCount =
    (mr?.persistence ?? []).length +
    sectionsForTab(mr?.sections, "persistence", report.section_tabs).length +
    (mr?.dynamic?.sandbox_signatures ?? []).filter((s) => viewKeeps("persistence", s.technique_ids ?? [], tactics)).length;
  const evasionCount = (mr?.dynamic?.sandbox_signatures ?? []).filter((s) =>
    viewKeeps("defence-evasion", s.technique_ids ?? [], tactics),
  ).length;
  const counts: Record<BehaviourView, number | null> = {
    all: null,
    persistence: persistenceCount,
    "defence-evasion": evasionCount,
  };

  return (
    <>
      <div role="group" aria-label="Behaviour shown" className="flex flex-wrap items-center gap-1">
        {VIEWS.map((v) => (
          <button
            key={v.key}
            type="button"
            aria-pressed={view === v.key}
            onClick={() => setView(v.key)}
            className={`rounded border px-2.5 py-1 text-xs ${
              view === v.key
                ? "border-accent bg-bg-active text-text-primary"
                : "border-border text-text-secondary hover:text-text-primary"
            }`}
          >
            {v.label}
            {counts[v.key] != null && <span className="ml-1 text-text-muted">{counts[v.key]}</span>}
          </button>
        ))}
      </div>

      <div id="dynamic" className="scroll-mt-40">
        <ProcessesBlock report={report} />
      </div>

      {/* Where the old persistence page and the defence-evasion view land:
          the behaviours, in that view. One box under three names, so each
          anchor scrolls to the same place. */}
      <div id="behaviours" className="scroll-mt-40">
        <div id="persistence" className="scroll-mt-40">
          <div id="defence-evasion" className="scroll-mt-40">
            <BehavioursBlock report={report} roster={job?.roster} view={view} tactics={tactics} />
          </div>
        </div>
      </div>

      <div id="attack" className="scroll-mt-40">
        <AttackContent view={view} empty={!tabHasContent("/capabilities", report, job?.roster)} />
      </div>

      {report.malware_report && hasTechnicalAnalysis(report.malware_report) ? (
        <div id="technical-analysis" className="scroll-mt-40">
          <TechnicalAnalysisPanel report={report.malware_report} />
        </div>
      ) : (
        <TabBlock id="technical-analysis" title="Technical analysis" empty />
      )}
    </>
  );
}
