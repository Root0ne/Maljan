"use client";

import { useState, useEffect } from "react";

import { api } from "@/lib/api";
import CopyButton from "@/components/ui/CopyButton";
import { getErrorMessage } from "@/lib/errors";
import { useReport } from "@/components/analysis/AnalysisContext";
import { RawJson } from "@/components/analysis/StructuredValue";
import StixGraphView from "@/components/analysis/StixGraph";
import {
  GRAPH_FIRST_LIMIT,
  bundleObjects,
  graphViewHint,
  readStixAnswer,
  stixFetchNotice,
} from "@/components/analysis/stixGraph";

type View = "graph" | "table" | "json";

const VIEWS: { key: View; label: string }[] = [
  { key: "graph", label: "Graph" },
  { key: "table", label: "Table" },
  { key: "json", label: "JSON" },
];

export default function StixPanel() {
  const { report, job, loading } = useReport();
  const [stixData, setStixData] = useState<Record<string, unknown> | null>(null);
  // The fetch used to fail silently; a refused copy says so beside its
  // button (`CopyButton`).
  const [fetchError, setFetchError] = useState<string | null>(null);
  // Nothing chosen yet means the view the bundle's size opens on, read on
  // every render so a bundle that arrives after the stored copy decides it.
  const [chosen, setChosen] = useState<View | null>(null);

  useEffect(() => {
    if (report?.id) {
      api.getReportStix(report.id)
        .then((data) => {
          setStixData(data);
          setFetchError(null);
        })
        .catch((err: unknown) =>
          setFetchError(getErrorMessage(err)),
        );
    }
  }, [report?.id]);

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading…</div>;
  }
  if (!report && job?.status !== "completed") {
    return (
      <div className="p-4 text-sm text-text-secondary animate-pulse">
        {job?.status === "failed"
          ? "Analysis failed; no STIX bundle was produced."
          : "Waiting for STIX bundle generation…"}
      </div>
    );
  }

  const { bundle, draft, notice } = readStixAnswer(stixData ?? report?.stix_bundle ?? {});
  const raw = JSON.stringify(bundle, null, 2);
  const objectCount = bundleObjects(bundle).length;
  const large = objectCount > GRAPH_FIRST_LIMIT;
  const view: View = chosen ?? (large ? "table" : "graph");

  return (
    <div className="bg-bg-surface border border-border rounded">
      {/* The heading used to be repeated here, directly under
          the parent DETECTION tab's "STIX 2.1 bundle (export)" heading. */}
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-border">
        {/* One segmented control: the three views are one choice. */}
        <div role="group" aria-label="How the bundle is shown" className="inline-flex overflow-hidden rounded border border-border">
          {VIEWS.map((v) => (
            <button
              key={v.key}
              type="button"
              aria-pressed={view === v.key}
              title={v.key === "graph" ? (graphViewHint(objectCount) ?? undefined) : undefined}
              onClick={() => setChosen(v.key)}
              className={`min-h-6 border-l border-border px-2.5 py-1 text-xs first:border-l-0 ${
                view === v.key
                  ? "bg-bg-active font-medium text-text-primary"
                  : "text-text-secondary hover:bg-bg-hover hover:text-text-primary"
              }`}
            >
              {v.label}
            </button>
          ))}
        </div>
        {graphViewHint(objectCount) && (
          <span className="text-[11px] text-text-muted">{graphViewHint(objectCount)}</span>
        )}
        <span className="flex-1" />
        <CopyButton value={raw} what="the STIX bundle as JSON" label="Copy JSON" />
      </div>
      {/* The bundle and the ATT&CK Navigator layer download from the page's
          one Export menu; a second pair of buttons here exported the same
          two files again. */}
      <p className="px-4 pt-3 text-[11px] text-text-muted">
        To download the bundle or the ATT&amp;CK Navigator layer, use Export at the top of the page.
      </p>
      {draft && (
        <div
          role="status"
          className="mx-4 mt-3 text-xs text-status-orange bg-status-orange/10 border border-status-orange/20 rounded px-2 py-1.5"
        >
          {notice ?? "This is the analysis's unpublished draft, not the export."}
        </div>
      )}
      {fetchError !== null && (
        <div
          role="alert"
          className="mx-4 mt-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
        >
          {stixFetchNotice(fetchError, Boolean(report?.stix_bundle))}
        </div>
      )}
      {view === "json" ? (
        <div className="p-4">
          <RawJson value={bundle} name="STIX bundle" />
        </div>
      ) : (
        <div className="p-4 space-y-3">
          <p className="text-xs text-text-muted">
            Every object and relationship in the exported bundle, and nothing
            else: an edge is one of the bundle&apos;s relationship or sighting
            objects, its confidence is printed only where the bundle states
            one, and where a node sits is layout, not a finding. An object the
            export declined is not in the bundle, so it is not here; the
            run&apos;s validation findings name it.
          </p>
          {large && (
            <p role="status" className="text-xs text-text-secondary">
              This bundle holds {objectCount} objects, more than the{" "}
              {GRAPH_FIRST_LIMIT} the graph draws on open, so it opens on the
              table.{" "}
              {view === "table" && (
                <button
                  type="button"
                  onClick={() => setChosen("graph")}
                  className="text-accent-strong hover:underline"
                >
                  Draw the graph
                </button>
              )}
            </p>
          )}
          <StixGraphView bundle={bundle} showGraph={view === "graph"} />
        </div>
      )}
    </div>
  );
}
