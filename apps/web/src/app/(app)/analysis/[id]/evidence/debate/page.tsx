"use client";

import DebateView from "@/components/analysis/DebateView";
import ReportGate from "@/components/analysis/ReportGate";

/** How the analysts argued their findings out: the outcome, each round, each report. */
export default function DebatePage() {
  return <ReportGate>{(report) => <DebateView report={report} />}</ReportGate>;
}
