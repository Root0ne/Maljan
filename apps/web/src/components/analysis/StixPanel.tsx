"use client";

import { useState, useEffect } from "react";

import { api } from "@/lib/api";
import { copyToClipboard, downloadBlob } from "@/lib/report-utils";
import { getErrorMessage } from "@/lib/errors";
import { useReport } from "@/app/(app)/analysis/[id]/layout";
import JsonNode from "@/components/analysis/JsonTree";
import StixGraphView from "@/components/analysis/StixGraph";
import { GRAPH_FIRST_LIMIT, bundleObjects } from "@/components/analysis/stixGraph";

type View = "graph" | "table" | "json";

const VIEWS: { key: View; label: string }[] = [
  { key: "graph", label: "Graph" },
  { key: "table", label: "Table" },
  { key: "json", label: "JSON" },
];

export default function StixPanel() {
  const { report, job, loading } = useReport();
  const [stixData, setStixData] = useState<Record<string, unknown> | null>(null);
  const [copied, setCopied] = useState(false);
  // The fetch and the copy
  // button both used to fail silently.
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
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
          setFetchError(
            `Could not fetch the freshly rendered STIX bundle (${getErrorMessage(err)}). Showing the stored copy.`,
          ),
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

  const bundle = stixData ?? report?.stix_bundle ?? {};
  const raw = JSON.stringify(bundle, null, 2);
  const objectCount = bundleObjects(bundle).length;
  const large = objectCount > GRAPH_FIRST_LIMIT;
  const view: View = chosen ?? (large ? "table" : "graph");

  return (
    <div className="bg-bg-surface border border-border rounded">
      {/* The heading used to be repeated here, directly under
          the parent DETECTION tab's "STIX 2.1 bundle (export)" heading. */}
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-border">
        <div role="group" aria-label="How the bundle is shown" className="flex gap-1">
          {VIEWS.map((v) => (
            <button
              key={v.key}
              type="button"
              aria-pressed={view === v.key}
              onClick={() => setChosen(v.key)}
              className={`rounded border px-2.5 py-1 text-xs ${
                view === v.key
                  ? "border-accent text-accent"
                  : "border-border text-text-secondary hover:text-text-primary"
              }`}
            >
              {v.label}
            </button>
          ))}
        </div>
        <span className="flex-1" />
        <button
          onClick={async () => {
            if (await copyToClipboard(raw)) {
              setActionError(null);
              setCopied(true);
              setTimeout(() => setCopied(false), 1500);
            } else {
              setActionError("Could not copy to the clipboard — copy the JSON below manually.");
            }
          }}
          className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted"
        >
          {copied ? "copied" : "Copy JSON"}
        </button>
        <button
          onClick={() =>
            downloadBlob(raw, "maljan-stix-bundle.json", "application/json")
          }
          className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted"
        >
          Download
        </button>
      </div>
      {(fetchError || actionError) && (
        <div
          role="alert"
          className="mx-4 mt-3 text-xs text-status-red bg-status-red/10 border border-status-red/20 rounded px-2 py-1.5"
        >
          {actionError ?? fetchError}
        </div>
      )}
      {view === "json" ? (
        <div className="p-4 font-mono text-xs leading-relaxed overflow-x-auto">
          <JsonNode data={bundle} />
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
