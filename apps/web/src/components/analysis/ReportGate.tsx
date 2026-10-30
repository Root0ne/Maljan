"use client";

import { useEffect, type ReactNode } from "react";
import type { ReportDetailDTO } from "@/lib/api";
import { useReport } from "./AnalysisContext";
import ReportAbsent from "./ReportAbsent";
import { reportAbsence } from "./reportAbsence";
import { anchorFromHash } from "./overview";

/**
 * What a tab draws before it has a report to draw from: "Loading", or which
 * absence this is (`reportAbsence`), said once for the whole tab rather than
 * once per block in it.
 */
export default function ReportGate({ children }: { children: (report: ReportDetailDTO) => ReactNode }) {
  const { report, job, loading, reportError } = useReport();
  if (loading) return <p className="text-sm text-text-muted">Loading the analysis…</p>;
  const absent = reportAbsence({ report, job, reportError });
  if (absent || !report) {
    return <ReportAbsent absence={absent ?? { kind: "none", text: "This analysis stored no report." }} />;
  }
  return (
    <div className="space-y-8">
      {children(report)}
      <ScrollToAnchor />
    </div>
  );
}

/* A link to a block (`/behaviour#persistence`, which is where an old route
 * lands) names an element the browser looked for before the report arrived.
 * Once the blocks are drawn, the one it names is brought into view. */
export function ScrollToAnchor() {
  useEffect(() => {
    const id = anchorFromHash(window.location.hash);
    if (id) document.getElementById(id)?.scrollIntoView({ block: "start" });
  }, []);
  return null;
}
