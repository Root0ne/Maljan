"use client";

import { useParams } from "next/navigation";

import { useReport } from "@/components/analysis/AnalysisContext";
import AnalystFindings from "./AnalystFindings";
import { ArtifactSections } from "./ArtifactTable";
import ReportAbsent from "./ReportAbsent";
import { extraTabs, tabByParam, type ExtraTabKind } from "./extraTabs";
import { reportAbsence } from "./reportAbsence";

/**
 * The page of one tab a run added for an agent or a server of its own
 * (`extraTabs`): the agent's claims in full, then the sections it owns.
 *
 * One page for both kinds, because both draw the same two things; the route
 * says which key is meant.
 */
export default function ExtraTabPage({ kind }: { kind: ExtraTabKind }) {
  const params = useParams();
  const { report, job, loading, reportError } = useReport();
  const param = typeof params?.key === "string" ? params.key : "";

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }
  const absent = reportAbsence({ report, job, reportError });
  if (absent) return <ReportAbsent absence={absent} />;

  const tab = tabByParam(
    extraTabs(
      report?.malware_report?.sections,
      report?.section_tabs,
      report?.agent_findings,
      job?.roster,
    ),
    kind,
    param,
  );
  if (!tab) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        This run recorded nothing under {param || "this name"}.
      </div>
    );
  }
  return (
    <div className="space-y-4">
      {tab.claims && <AnalystFindings findings={[tab.claims]} />}
      <ArtifactSections sections={tab.sections} showKey />
    </div>
  );
}
