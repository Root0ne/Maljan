"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useMemo } from "react";
import { GitCompareArrows } from "lucide-react";
import { useReport } from "@/components/analysis/AnalysisContext";
import { evidenceViews } from "@/components/analysis/extraTabs";
import { analysisHref } from "@/components/analysis/overview";
import Tabs, { activeTabKey, type TabItem } from "@/components/ui/Tabs";

/**
 * Evidence: everything the report stands on, as views under one tab
 * (`evidenceViews`). The evidence bundle comes first; then the records every
 * citation resolves into; then the analysts' discussion with what each one
 * concluded; then one view per agent or tool server of the run's own whose
 * output no other tab draws.
 */
export default function EvidenceLayout({ children }: { children: React.ReactNode }) {
  const { jobId, report, job } = useReport();
  const pathname = usePathname() ?? "";
  const base = analysisHref(jobId, "evidence");

  const views = useMemo<TabItem[]>(
    () =>
      evidenceViews(report, job?.roster).map((v) => ({
        key: v.key || "first",
        label: v.label,
        href: `${base}${v.key}`,
      })),
    [report, job?.roster, base],
  );

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-3">
        <div className="min-w-0 flex-1">
          <Tabs tabs={views} active={activeTabKey(views, pathname)} label="Evidence views" />
        </div>
        {/* Only a finished run has a stored record to compare. */}
        {report && job?.status === "completed" && (
          <Link
            href={`/compare?a=${encodeURIComponent(jobId)}`}
            className="inline-flex items-center gap-1 pb-2 text-xs text-accent-strong hover:underline"
          >
            <GitCompareArrows size={16} aria-hidden="true" />
            Compare with another run
          </Link>
        )}
      </div>
      {children}
    </div>
  );
}
