"use client";

/* One server's tools, as a table the tick list is edited through.
 *
 * A row of tick boxes worked for three tools and not for the hundred and more a
 * disassembler's server offers: nothing found a tool by name, nothing turned
 * the lot on or off, and the reason a tool could not run on its host sat in a
 * separate list above. The table holds all three, and the count of what the
 * model may call is a live region, so a screen reader hears it change as the
 * boxes do. The rules — what "all" means for a built-in, what a search
 * narrows, what happens to a name the manifest dropped — are in
 * `toolTableRows.ts`.
 */

import { useId, useState } from "react";

import type { CapabilityCell } from "@/types/settings";
import { enabledCount, matchingTools, setTools, toolRows } from "./toolTableRows";

const BUTTON =
  "text-xs px-2 py-0.5 border border-border rounded text-text-secondary hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed";

export default function ToolTable({
  serverKey,
  manifest,
  allowed,
  cells,
  onChange,
}: {
  serverKey: string;
  /** Every tool the server offered on its last probe. */
  manifest: string[];
  /** The stored tick list; `null` is every tool. */
  allowed: string[] | null;
  /** The capability manifest's cells by tool, empty when it offers none. */
  cells: Map<string, CapabilityCell>;
  onChange: (tools: string[]) => void;
}) {
  const [query, setQuery] = useState("");
  const searchId = useId();
  const rows = toolRows(manifest, allowed, cells, query);
  const shown = matchingTools(manifest, query);
  const filtered = query.trim() !== "";
  const enabled = enabledCount(manifest, allowed);
  const hasCapabilities = cells.size > 0;
  const allOn = shown.every((tool) => allowed === null || allowed.includes(tool));
  const allOff = shown.every((tool) => allowed !== null && !allowed.includes(tool));

  return (
    <div className="mt-2 space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={searchId} className="sr-only">
          Search the tools of {serverKey}
        </label>
        <input
          id={searchId}
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search tools"
          className="min-w-0 flex-1 bg-bg-deep border border-border rounded px-2 py-1 text-xs text-text-primary focus:outline-none focus:border-accent"
        />
        <button
          type="button"
          className={BUTTON}
          disabled={shown.length === 0 || allOn}
          onClick={() => onChange(setTools(manifest, allowed, shown, true))}
        >
          {filtered ? "Select all shown" : "Select all"}
        </button>
        <button
          type="button"
          className={BUTTON}
          disabled={shown.length === 0 || allOff}
          onClick={() => onChange(setTools(manifest, allowed, shown, false))}
        >
          {filtered ? "Select none shown" : "Select none"}
        </button>
        <p role="status" className="text-xs text-text-secondary" data-tool-count={serverKey}>
          enabled {enabled} of {manifest.length}
          {filtered ? ` · ${shown.length} shown` : ""}
        </p>
      </div>

      {rows.length === 0 ? (
        <p className="text-xs text-text-muted">No tool of {serverKey} has &ldquo;{query.trim()}&rdquo; in its name.</p>
      ) : (
        <div className="overflow-x-auto max-h-80 overflow-y-auto border border-border rounded">
          <table className="w-full text-xs">
            <caption className="sr-only">Tools of {serverKey} the model may call</caption>
            <thead className="bg-bg-elevated text-text-muted">
              <tr>
                <th scope="col" className="px-2 py-1 text-left font-medium w-12">
                  Enabled
                </th>
                <th scope="col" className="px-2 py-1 text-left font-medium">
                  Tool
                </th>
                {hasCapabilities && (
                  <th scope="col" className="px-2 py-1 text-left font-medium">
                    On this host
                  </th>
                )}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {rows.map((row) => (
                <tr key={row.name} data-tool-row={row.name}>
                  <td className="px-2 py-1">
                    <input
                      type="checkbox"
                      aria-label={`${serverKey} tool ${row.name}`}
                      checked={row.enabled}
                      onChange={(e) =>
                        onChange(setTools(manifest, allowed, [row.name], e.target.checked))
                      }
                    />
                  </td>
                  <td className="px-2 py-1 font-mono text-text-primary break-all">{row.name}</td>
                  {hasCapabilities && (
                    <td className="px-2 py-1">
                      {row.available ? (
                        <span className="text-text-secondary">available</span>
                      ) : (
                        <>
                          <span className="text-status-orange">unavailable</span>
                          {row.reason && (
                            <span className="text-text-secondary">: {row.reason}</span>
                          )}
                        </>
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
