"use client";

import { useState } from "react";

/**
 * A JSON value printed as a collapsible tree: the STIX panel's raw view and
 * the graph's detail pane both read an object this way.
 */
export default function JsonNode({
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
