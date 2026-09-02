"use client";

import type { CatalogEntry } from "@/types/settings";

const APPLIES: Record<string, string> = {
  next_job: "takes effect on the next analysis",
  live: "takes effect immediately",
  restart: "needs a restart",
};

export default function ApplyBar({
  pending,
  entries,
  saving,
  onApply,
  onDiscard,
  confirming,
  setConfirming,
}: {
  pending: Record<string, unknown>;
  entries: Map<string, CatalogEntry>;
  saving: boolean;
  onApply: () => void;
  onDiscard: () => void;
  confirming: boolean;
  setConfirming: (b: boolean) => void;
}) {
  const keys = Object.keys(pending);
  if (keys.length === 0) return null;
  return (
    <div className="sticky bottom-0 mt-6 border-t border-border bg-bg-surface/95 backdrop-blur px-4 py-3 rounded-t">
      {confirming && (
        <ul className="text-xs text-text-secondary mb-3 space-y-1 max-h-40 overflow-auto">
          {keys.map((k) => {
            const e = entries.get(k);
            const v = pending[k];
            return (
              <li key={k}>
                <span className="font-mono">{k}</span>
                {" → "}
                {e?.secret ? (v === null ? "cleared" : "new secret") : JSON.stringify(v)}{" "}
                <span className="text-text-muted">({APPLIES[e?.applies ?? "next_job"]})</span>
              </li>
            );
          })}
        </ul>
      )}
      <div className="flex items-center gap-4 flex-wrap">
        <span className="text-sm text-text-primary">
          {keys.length} change{keys.length === 1 ? "" : "s"} pending
        </span>
        {!confirming ? (
          <button
            type="button"
            className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover transition-colors"
            onClick={() => setConfirming(true)}
          >
            Apply
          </button>
        ) : (
          <button
            type="button"
            disabled={saving}
            className="px-3 py-1.5 text-xs font-medium uppercase tracking-wider bg-accent text-white rounded hover:bg-accent-hover transition-colors disabled:opacity-50"
            onClick={onApply}
          >
            {saving ? "Saving…" : "Confirm and apply"}
          </button>
        )}
        <button
          type="button"
          className="text-xs text-text-secondary hover:text-text-primary"
          onClick={() => {
            setConfirming(false);
            onDiscard();
          }}
        >
          Discard
        </button>
      </div>
    </div>
  );
}
