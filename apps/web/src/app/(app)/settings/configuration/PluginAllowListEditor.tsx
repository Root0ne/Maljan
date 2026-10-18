"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { CatalogEntry, PluginsListing, SettingValue } from "@/types/settings";
import {
  TRUST_NOTE,
  WORKER_NOTE,
  absentEntries,
  allowListOf,
  pluginRows,
  withEntry,
  type StatusTone,
} from "./pluginAllowList";

const TONE_CLASS: Record<StatusTone, string> = {
  ok: "text-status-green",
  error: "text-status-red",
  muted: "text-text-muted",
};

export interface PluginAllowListViewProps {
  listing: PluginsListing | null;
  error: string | null;
  /** The list the next apply leaves: the staged value, else the saved one. */
  list: string[];
  editable: boolean;
  onChange: (list: string[]) => void;
}

/** Every installed plugin per kind with its package, version, status and the API's own load,
 *  and its tick box. */
export function PluginAllowListView({
  listing,
  error,
  list,
  editable,
  onChange,
}: PluginAllowListViewProps) {
  const absent = listing ? absentEntries(listing, list) : [];
  return (
    <div data-testid="plugin-allow-list" className="border border-border rounded px-3 py-2">
      <p className="text-[11px] text-text-secondary">{TRUST_NOTE}</p>
      <p className="text-[11px] text-text-muted mt-1">{WORKER_NOTE}</p>
      {error && (
        <p role="alert" className="text-[11px] text-status-red mt-2">
          The installed plugins could not be listed: {error}
        </p>
      )}
      {!listing && !error && (
        <p className="text-[11px] text-text-muted mt-2">Reading the installed plugins…</p>
      )}
      {listing?.kinds.map((kind) => {
        const rows = pluginRows(kind, list);
        return (
          <section key={kind.kind} data-plugin-kind={kind.kind} className="mt-3">
            <h4 className="text-xs text-text-primary">
              {kind.title} <span className="font-mono text-text-muted">{kind.group}</span>
            </h4>
            {rows.length === 0 ? (
              <p className="text-[11px] text-text-muted">No installed package declares one.</p>
            ) : (
              <table className="w-full text-[11px] mt-1">
                <thead className="text-text-muted text-left">
                  <tr>
                    <th className="font-normal pr-2">Allowed</th>
                    <th className="font-normal pr-2">Name</th>
                    <th className="font-normal pr-2">Package</th>
                    <th className="font-normal pr-2">Version</th>
                    <th className="font-normal pr-2">Status</th>
                    <th className="font-normal">API</th>
                  </tr>
                </thead>
                <tbody className="text-text-secondary">
                  {rows.map((row) => (
                    <tr key={row.entry} data-plugin={row.entry}>
                      <td className="pr-2">
                        <input
                          type="checkbox"
                          aria-label={`Allow ${row.entry}`}
                          checked={row.allowed}
                          disabled={!editable || (row.refused && !row.allowed)}
                          onChange={(e) => onChange(withEntry(list, row.entry, e.target.checked))}
                        />
                      </td>
                      <td className="pr-2 font-mono text-text-primary">{row.name}</td>
                      <td className="pr-2">{row.distribution || "unnamed package"}</td>
                      <td className="pr-2 font-mono">{row.version || "no version"}</td>
                      <td className={`pr-2 ${TONE_CLASS[row.tone]}`}>{row.status}</td>
                      <td className={TONE_CLASS[row.apiTone]}>{row.api}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        );
      })}
      {absent.length > 0 && (
        <div className="mt-3" data-testid="plugin-allow-list-absent">
          <p className="text-[11px] text-text-secondary">
            On the list, but no installed package declares it:
          </p>
          <ul className="text-[11px]">
            {absent.map((entry) => (
              <li key={entry} className="flex items-center gap-2 mt-1">
                <span className="font-mono text-text-primary">{entry}</span>
                <button
                  type="button"
                  className="h-6 rounded border border-border px-2 text-[11px] text-text-secondary hover:text-text-primary disabled:opacity-50"
                  disabled={!editable}
                  onClick={() => onChange(withEntry(list, entry, false))}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

/** The `plugins.allowed` editor: reads the installed plugins, stages the ticked entries. */
export default function PluginAllowListEditor({
  entry,
  current,
  staged,
  onChange,
}: {
  entry: CatalogEntry;
  current?: SettingValue;
  staged: unknown;
  onChange: (value: unknown) => void;
}) {
  const [listing, setListing] = useState<PluginsListing | null>(null);
  const [error, setError] = useState<string | null>(null);
  const saved = allowListOf(current?.value ?? entry.default);
  // Read again whenever the saved list changes: an apply loads in the API what
  // it allows at once, so the statuses are then the new ones.
  const savedKey = JSON.stringify(saved);
  useEffect(() => {
    let live = true;
    api.getSettingsPlugins().then(
      (read) => {
        if (!live) return;
        setListing(read);
        setError(null);
      },
      (e: unknown) => {
        if (live) setError(getErrorMessage(e));
      }
    );
    return () => {
      live = false;
    };
  }, [savedKey]);
  const list = staged !== undefined ? allowListOf(staged) : saved;
  return (
    <PluginAllowListView
      listing={listing}
      error={error}
      list={list}
      editable={entry.editable}
      onChange={onChange}
    />
  );
}
