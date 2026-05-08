"use client";

import { useState, useEffect } from "react";

import { api } from "@/lib/api";
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

export default function StixTab() {
  const { report, job, loading } = useReport();
  const [stixData, setStixData] = useState<Record<string, unknown> | null>(null);

  useEffect(() => {
    if (report?.id) {
      api.getReportStix(report.id)
        .then((data) => setStixData(data))
        .catch(() => {});
    }
  }, [report?.id]);

  if (loading || (!report && job?.status !== "completed")) {
    return <div className="p-4 text-sm text-text-secondary animate-pulse">Waiting for STIX bundle generation...</div>;
  }

  const bundle = stixData ?? report?.stix_bundle ?? {};
  const raw = JSON.stringify(bundle, null, 2);

  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="flex items-center justify-between px-4 py-3 border-b border-border">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          STIX 2.1 Bundle
        </h2>
        <div className="flex gap-2">
          <button
            onClick={() => navigator.clipboard.writeText(raw)}
            className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors"
          >
            Copy JSON
          </button>
          <button
            onClick={() => {
              const blob = new Blob([raw], { type: "application/json" });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = "maljan-stix-bundle.json";
              a.click();
              URL.revokeObjectURL(url);
            }}
            className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors"
          >
            Download
          </button>
        </div>
      </div>
      <div className="p-4 font-mono text-xs leading-relaxed overflow-x-auto">
        <JsonNode data={bundle} />
      </div>
    </div>
  );
}
