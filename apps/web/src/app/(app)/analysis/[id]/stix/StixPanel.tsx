"use client";

import { useState, useEffect } from "react";

import { api } from "@/lib/api";
import { copyToClipboard, downloadBlob } from "@/lib/report-utils";
import { getErrorMessage } from "@/lib/errors";
import { useReport } from "../layout";

function JsonNode({
  data,
  depth = 0,
}: {
  data: unknown;
  depth?: number;
}) {
  const [collapsed, setCollapsed] = useState(depth > 2);
  const indent = depth * 16;

  if (data === null) return <span className="text-text-muted">null</span>;
  if (typeof data === "boolean")
    return <span className="text-status-orange">{data.toString()}</span>;
  if (typeof data === "number")
    return <span className="text-status-green">{data}</span>;
  if (typeof data === "string")
    return <span className="text-status-blue">&quot;{data}&quot;</span>;

  if (Array.isArray(data)) {
    if (data.length === 0) return <span className="text-text-muted">[]</span>;
    if (collapsed) {
      return (
        <span>
          <button
            onClick={() => setCollapsed(false)}
            className="text-text-muted hover:text-text-primary"
          >
            [{data.length} items...]
          </button>
        </span>
      );
    }
    return (
      <span>
        <button
          onClick={() => setCollapsed(true)}
          className="text-text-muted hover:text-text-primary"
        >
          [
        </button>
        {data.map((item, i) => (
          <div key={i} style={{ paddingLeft: indent + 16 }}>
            <JsonNode data={item} depth={depth + 1} />
            {i < data.length - 1 && <span className="text-text-muted">,</span>}
          </div>
        ))}
        <div style={{ paddingLeft: indent }}>
          <span className="text-text-muted">]</span>
        </div>
      </span>
    );
  }

  if (typeof data === "object") {
    const entries = Object.entries(data as Record<string, unknown>);
    if (entries.length === 0)
      return <span className="text-text-muted">{"{}"}</span>;
    if (collapsed) {
      return (
        <span>
          <button
            onClick={() => setCollapsed(false)}
            className="text-text-muted hover:text-text-primary"
          >
            {"{"} {entries.length} keys... {"}"}
          </button>
        </span>
      );
    }
    return (
      <span>
        <button
          onClick={() => setCollapsed(true)}
          className="text-text-muted hover:text-text-primary"
        >
          {"{"}
        </button>
        {entries.map(([key, val], i) => (
          <div key={key} style={{ paddingLeft: indent + 16 }}>
            <span className="text-status-purple">&quot;{key}&quot;</span>
            <span className="text-text-muted">: </span>
            <JsonNode data={val} depth={depth + 1} />
            {i < entries.length - 1 && (
              <span className="text-text-muted">,</span>
            )}
          </div>
        ))}
        <div style={{ paddingLeft: indent }}>
          <span className="text-text-muted">{"}"}</span>
        </div>
      </span>
    );
  }

  return <span className="text-text-muted">{String(data)}</span>;
}

export default function StixPanel() {
  const { report, job, loading } = useReport();
  const [stixData, setStixData] = useState<Record<string, unknown> | null>(null);
  const [copied, setCopied] = useState(false);
  // audit 2026-07-26 (§4 "sessizce yutulan hatalar"): the fetch and the copy
  // button both used to fail silently.
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

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

  return (
    <div className="bg-bg-surface border border-border rounded">
      {/* audit 2026-07-26: the heading used to be repeated here, directly under
          the parent DETECTION tab's "STIX 2.1 bundle (export)" heading. */}
      <div className="flex items-center justify-end gap-2 px-4 py-3 border-b border-border">
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
          className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors"
        >
          {copied ? "copied" : "Copy JSON"}
        </button>
        <button
          onClick={() =>
            downloadBlob(raw, "maljan-stix-bundle.json", "application/json")
          }
          className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors"
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
      <div className="p-4 font-mono text-xs leading-relaxed overflow-x-auto">
        <JsonNode data={bundle} />
      </div>
    </div>
  );
}
