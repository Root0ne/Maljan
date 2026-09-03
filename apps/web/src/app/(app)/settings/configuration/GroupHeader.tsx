"use client";

import { useState } from "react";
import type { ProbeResult, SettingValue, SettingsGroup } from "@/types/settings";

const PROBE_LABEL: Record<string, string> = {
  llm: "Test connection & fetch models",
};

export default function GroupHeader({
  group,
  values,
  probes,
  onProbe,
  onResetGroup,
}: {
  group: SettingsGroup;
  values: Record<string, SettingValue>;
  probes: string[];
  onProbe: (name: string) => Promise<ProbeResult>;
  onResetGroup: () => Promise<void>;
}) {
  const [results, setResults] = useState<Record<string, ProbeResult | "running" | undefined>>({});
  // "editable" only says a UI-override is *permitted*; it does not mean one
  // exists. The reset action must only appear once a row actually carries a
  // ui-sourced override to reset away.
  const overridden = group.entries.some((e) => values[e.key]?.source === "ui");
  return (
    <div className="flex items-center justify-between gap-4 mb-2 flex-wrap">
      <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
        {group.title}
      </h2>
      <div className="flex items-center gap-3 flex-wrap">
        {probes.map((name) => {
          const r = results[name];
          return (
            <span key={name} className="flex items-center gap-2">
              <button
                type="button"
                className="text-xs text-accent-strong disabled:opacity-50"
                disabled={r === "running"}
                onClick={async () => {
                  setResults((s) => ({ ...s, [name]: "running" }));
                  const res = await onProbe(name).catch((e) => ({
                    ok: false,
                    latency_ms: 0,
                    detail: String(e),
                    models: null,
                  }));
                  setResults((s) => ({ ...s, [name]: res }));
                }}
              >
                {PROBE_LABEL[name] ?? `Test ${name}`}
              </button>
              {r && r !== "running" && (
                <span
                  className={`text-[11px] ${r.ok ? "text-status-green" : "text-status-red"}`}
                  role="status"
                >
                  {r.ok ? "ok" : "failed"} · {r.latency_ms} ms · {r.detail}
                </span>
              )}
              {r === "running" && <span className="text-[11px] text-text-muted">testing…</span>}
            </span>
          );
        })}
        {overridden && (
          <button
            type="button"
            className="text-[11px] text-text-secondary"
            onClick={() => void onResetGroup()}
          >
            Reset group to env
          </button>
        )}
      </div>
    </div>
  );
}
