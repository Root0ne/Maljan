"use client";

import { notFound, useParams } from "next/navigation";
import OverviewTab from "@/components/preview/OverviewTab";
import PlaceholderTab from "@/components/preview/PlaceholderTab";
import { tabForSegment } from "@/components/preview/overview";

/** One tab of the preview, named by the optional path segment; Overview without one. */
export default function AnalysisPreviewTab() {
  const params = useParams();
  const raw = params.tab;
  const segments = Array.isArray(raw) ? raw : raw ? [raw] : [];
  const tab = segments.length > 1 ? null : tabForSegment(segments[0]);
  if (!tab) notFound();
  return tab.key === "overview" ? <OverviewTab /> : <PlaceholderTab tab={tab} />;
}
