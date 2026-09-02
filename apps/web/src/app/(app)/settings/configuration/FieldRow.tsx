"use client";

import type { CatalogEntry, SettingValue } from "@/types/settings";
import { Widget } from "./widgets";

const APPLIES: Record<string, string> = {
  next_job: "next analysis",
  live: "immediately",
  restart: "restart required",
};

const SOURCE: Record<string, string> = { default: "default", env: "env", ui: "ui" };

export default function FieldRow({
  entry,
  current,
  staged,
  error,
  onChange,
  onUnstage,
  onReset,
  models,
}: {
  entry: CatalogEntry;
  current?: SettingValue;
  staged: unknown;
  error?: string;
  models?: string[];
  onChange: (v: unknown) => void;
  onUnstage: () => void;
  onReset: () => void;
}) {
  const dirty = staged !== undefined;
  const source = current?.source ?? "default";
  const labelId = `setting-label-${entry.key}`;
  return (
    <div
      id={`setting-${entry.key}`}
      className={`grid grid-cols-1 sm:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] gap-2 sm:gap-4 py-3 border-b border-border ${
        dirty ? "bg-accent/5" : ""
      }`}
    >
      <div>
        <div className="flex items-center gap-2 flex-wrap">
          <span id={labelId} className="text-sm text-text-primary">
            {entry.title}
          </span>
          <span
            className={`text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded ${
              source === "ui"
                ? "bg-accent/20 text-accent-strong"
                : source === "env"
                  ? "bg-status-orange/10 text-status-orange"
                  : "bg-border text-text-muted"
            }`}
          >
            {SOURCE[source]}
          </span>
          <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-border text-text-muted">
            {APPLIES[entry.applies]}
          </span>
          {dirty && (
            <span className="text-[10px] uppercase tracking-wider text-accent-strong">
              modified
            </span>
          )}
        </div>
        <button
          type="button"
          className="text-[11px] font-mono text-text-muted hover:text-text-secondary"
          title="Copy key"
          onClick={() => void navigator.clipboard?.writeText(entry.key)}
        >
          {entry.key}
        </button>
        <p className="text-xs text-text-secondary mt-1">{entry.description}</p>
        {!entry.editable && entry.reason && (
          <p className="text-[11px] text-text-muted mt-1">{entry.reason}</p>
        )}
      </div>
      <div>
        <div role="group" aria-labelledby={labelId}>
          <Widget entry={entry} current={current} staged={staged} onChange={onChange} models={models} />
        </div>
        {error && (
          <div className="text-[11px] text-status-red mt-1" role="alert">
            {error}
          </div>
        )}
        <div className="flex gap-3 mt-1">
          {dirty && (
            <button type="button" className="text-[11px] text-text-secondary" onClick={onUnstage}>
              Discard change
            </button>
          )}
          {source === "ui" && entry.editable && (
            <button type="button" className="text-[11px] text-text-secondary" onClick={onReset}>
              Reset to env
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
