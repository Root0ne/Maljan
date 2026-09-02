"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import ApplyBar from "./ApplyBar";
import FieldRow from "./FieldRow";
import GroupHeader from "./GroupHeader";
import { useSettings } from "./useSettings";

const APPLIES_LABEL: Record<string, string> = {
  next_job: "on the next analysis",
  live: "immediately",
  restart: "after a restart",
};

/** Triggers a browser download of `text` as `filename` — no server round trip
 * beyond the fetch already made; the viewer never sees a bare data: link. */
function downloadText(filename: string, text: string) {
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default function ConfigurationTab() {
  const s = useSettings();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [toast, setToast] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  useEffect(() => {
    const dirty = Object.keys(s.pending).length > 0;
    const handler = (e: BeforeUnloadEvent) => {
      if (dirty) e.preventDefault();
    };
    window.addEventListener("beforeunload", handler);
    return () => window.removeEventListener("beforeunload", handler);
  }, [s.pending]);

  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(null), 3000);
    return () => clearTimeout(t);
  }, [toast]);

  const visibleGroups = useMemo(() => {
    if (!s.schema) return [];
    const q = query.trim().toLowerCase();
    return s.schema.groups
      .map((g) => ({
        ...g,
        entries: q
          ? g.entries.filter((e) =>
              [e.key, e.title, e.description].some((t) => t.toLowerCase().includes(q))
            )
          : g.entries,
      }))
      .filter((g) => g.entries.length > 0 && (q || !active || g.key === active));
  }, [s.schema, query, active]);

  if (s.loading) {
    return <div className="text-sm text-text-secondary">Loading configuration…</div>;
  }
  if (s.forbidden) {
    return (
      <div className="text-sm text-text-secondary" role="alert">
        Configuration is available to administrators only (admin role required).
      </div>
    );
  }
  if (s.loadError) {
    return (
      <div className="text-sm text-status-red" role="alert">
        {s.loadError}
      </div>
    );
  }
  if (!s.schema) return null;

  const groupKey = active ?? s.schema.groups[0]?.key ?? null;

  return (
    <div>
      <div className="flex items-center justify-between gap-4 mb-4 flex-wrap">
        <div className="flex-1 min-w-[240px]">
          <label htmlFor="settings-search" className="sr-only">
            Search settings
          </label>
          <input
            id="settings-search"
            type="search"
            placeholder="Search settings (key, title, description)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full bg-bg-deep border border-border rounded px-3 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent"
          />
        </div>
        {!s.schema.secrets_available && (
          <span className="text-[11px] text-status-orange">
            SETTINGS_ENCRYPTION_KEY is not set: secrets are read-only
          </span>
        )}
        <button
          type="button"
          className="text-xs text-accent-strong shrink-0"
          onClick={async () => {
            setExportError(null);
            try {
              const text = await api.exportSettings();
              downloadText("maljan-settings.env", text);
              setToast("Overrides downloaded as maljan-settings.env");
            } catch (e) {
              setExportError(getErrorMessage(e));
            }
          }}
        >
          Export overrides (.env)
        </button>
      </div>
      {exportError && (
        <div className="text-xs text-status-red mb-3" role="alert">
          {exportError}
        </div>
      )}
      {s.lastResult && (
        <div className="text-xs text-status-green mb-3" role="status">
          Applied {s.lastResult.applied.length} setting
          {s.lastResult.applied.length === 1 ? "" : "s"}
          {Object.entries(s.lastResult.applies)
            .filter(([, count]) => count && count > 0)
            .map(([bucket, count]) => ` · ${count} ${APPLIES_LABEL[bucket] ?? bucket}`)
            .join("")}
        </div>
      )}
      {toast && (
        <div className="text-xs text-text-secondary mb-3" role="status">
          {toast}
        </div>
      )}
      <div className="grid grid-cols-1 lg:grid-cols-[200px_minmax(0,1fr)] gap-6">
        <nav aria-label="Setting groups" className="flex lg:block gap-1 overflow-x-auto lg:overflow-visible lg:space-y-1">
          {s.schema.groups.map((g) => {
            const dirty = g.entries.some((e) => e.key in s.pending);
            return (
              <button
                key={g.key}
                type="button"
                onClick={() => {
                  setActive(g.key);
                  setQuery("");
                }}
                aria-current={!query && groupKey === g.key ? "true" : undefined}
                className={`w-full text-left px-2 py-1.5 text-xs rounded whitespace-nowrap lg:whitespace-normal ${
                  !query && groupKey === g.key
                    ? "bg-bg-active text-text-primary"
                    : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
                }`}
              >
                {g.title}
                {dirty ? " •" : ""}
              </button>
            );
          })}
        </nav>
        <div className="min-w-0">
          {visibleGroups.length === 0 && (
            <p className="text-sm text-text-muted">No settings match &ldquo;{query}&rdquo;.</p>
          )}
          {visibleGroups.map((g) => {
            const probes = Array.from(
              new Set(g.entries.map((e) => e.probe).filter((p): p is string => Boolean(p)))
            );
            return (
              <section key={g.key} className="mb-8">
                <GroupHeader
                  group={g}
                  values={s.values}
                  probes={probes}
                  onProbe={async (name) => {
                    const keys = g.entries.filter((e) => e.probe === name).map((e) => e.key);
                    const r = await s.probe(name, keys);
                    if (r.models) setModels(r.models);
                    return r;
                  }}
                  onResetGroup={() => s.resetGroup(g.key)}
                />
                {g.entries.map((e) => (
                  <FieldRow
                    key={e.key}
                    entry={e}
                    current={s.values[e.key]}
                    staged={s.pending[e.key]}
                    error={s.errors[e.key]}
                    models={e.probe === "llm" ? models : undefined}
                    onChange={(v) => s.stage(e.key, v)}
                    onUnstage={() => s.unstage(e.key)}
                    onReset={() => void s.reset(e.key)}
                  />
                ))}
              </section>
            );
          })}
        </div>
      </div>
      <ApplyBar
        pending={s.pending}
        entries={s.entries}
        saving={s.saving}
        confirming={confirming}
        setConfirming={setConfirming}
        onApply={async () => {
          const r = await s.apply();
          if (r) setConfirming(false);
        }}
        onDiscard={() => Object.keys(s.pending).forEach((k) => s.unstage(k))}
      />
    </div>
  );
}
