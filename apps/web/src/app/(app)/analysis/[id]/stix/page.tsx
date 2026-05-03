"use client";

import { useState } from "react";

const MOCK_STIX = {
  type: "bundle",
  id: "bundle--a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  objects: [
    {
      type: "malware",
      id: "malware--1234-5678-9abc-def012345678",
      name: "Emotet",
      description: "Banking trojan turned modular botnet loader",
      malware_types: ["trojan", "bot"],
      is_family: true,
    },
    {
      type: "indicator",
      id: "indicator--abcd-1234-5678-9abcdef01234",
      name: "Emotet C2 IP",
      pattern: "[ipv4-addr:value = '185.x.x.x']",
      pattern_type: "stix",
      valid_from: "2026-04-28T00:00:00Z",
    },
    {
      type: "attack-pattern",
      id: "attack-pattern--t1055",
      name: "Process Injection",
      external_references: [
        { source_name: "mitre-attack", external_id: "T1055" },
      ],
    },
    {
      type: "relationship",
      id: "relationship--r1",
      relationship_type: "uses",
      source_ref: "malware--1234-5678-9abc-def012345678",
      target_ref: "attack-pattern--t1055",
    },
  ],
};

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
  const raw = JSON.stringify(MOCK_STIX, null, 2);

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
        <JsonNode data={MOCK_STIX} />
      </div>
    </div>
  );
}
