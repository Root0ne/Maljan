"use client";

import { useMemo, useState } from "react";

import { useReport } from "../layout";
import type { CapabilityCell } from "@/types/malware-report";

/* MITRE Enterprise tactics — fixed order matches the ATT&CK Navigator. */
const ENTERPRISE_TACTICS: { id: string; name: string }[] = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Dev" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Esc" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command & Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
];

function cellColor(confidence: number): string {
  if (confidence <= 0) return "#1f2126";
  // gradient from dim grey → status-red
  const c = Math.min(1, Math.max(0, confidence));
  // base #2a2c33 → #ff7b72 (new --status-red), simple lerp on RGB
  const start = { r: 42, g: 44, b: 51 };
  const end = { r: 255, g: 123, b: 114 };
  const r = Math.round(start.r + (end.r - start.r) * c);
  const g = Math.round(start.g + (end.g - start.g) * c);
  const b = Math.round(start.b + (end.b - start.b) * c);
  return `rgb(${r}, ${g}, ${b})`;
}

export default function CapabilitiesTab() {
  const { report, loading } = useReport();
  const [selectedKey, setSelectedKey] = useState<string | null>(null);

  const cells: CapabilityCell[] = report?.malware_report?.capability_matrix ?? [];
  // Wave 4: transparency on platform-aware drops. The cascade now logs
  // every technique it rejected for platform-incompatibility so the user
  // knows why the matrix is sparser than the analyst reports might suggest.
  // Wave 9: ``run_summary`` is now narrowed to ``RunSummary`` so the
  // inline cast can be removed.
  const dropped =
    report?.malware_report?.run_summary?.cascade?.dropped_by_platform ?? [];
  const sampleIdentityPlatform =
    report?.malware_report?.identity?.platform ?? "unknown";
  // Wave 10 W10-OBS-03 (2026-05-30): surface the pre-cascade Sigma/YARA
  // Layer-0 filter counters from ``run_summary.cascade.platform_filter_summary``.
  // The Wave 9 audit gate G-FP-8 introduced the field; the UI now renders
  // it as a footer note so operators can see at a glance how many rules
  // the platform pre-filter dropped (e.g. sigma_dropped=2938 on a clean
  // Android APK run, proving the Windows-targeted Sigma corpus did not
  // poison the cascade).
  const pfs = report?.malware_report?.run_summary?.cascade?.platform_filter_summary;
  const platformFilterBanner = pfs ? (
    <div className="bg-bg-surface border border-border rounded px-4 py-2 text-[11px] text-text-muted">
      Sigma {pfs.sigma_dropped} + YARA {pfs.yara_dropped} rule
      {pfs.sigma_dropped + pfs.yara_dropped === 1 ? "" : "s"} pre-filtered for
      sample platform <span className="text-text-secondary">{pfs.sample_platform}</span>
      {" "}
      (Layer 0 platform-aware filter)
    </div>
  ) : null;

  /* Bucket cells by tactic id; preserve insertion order inside each bucket. */
  const grid = useMemo(() => {
    const byTactic = new Map<string, CapabilityCell[]>();
    for (const c of cells) {
      if (!byTactic.has(c.tactic)) byTactic.set(c.tactic, []);
      byTactic.get(c.tactic)!.push(c);
    }
    return ENTERPRISE_TACTICS.map((t) => ({
      tactic: t,
      cells: byTactic.get(t.id) ?? [],
    }));
  }, [cells]);

  const maxRows = Math.max(1, ...grid.map((col) => col.cells.length));
  const selected =
    selectedKey === null
      ? null
      : cells.find((c) => `${c.tactic}:${c.technique_id}` === selectedKey) ?? null;

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  if (cells.length === 0) {
    return (
      <div className="space-y-4">
        {platformFilterBanner}
        <div className="p-8 text-center text-sm text-text-secondary">
          No ATT&amp;CK techniques have been mapped to this sample yet.
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {platformFilterBanner}
      {dropped.length > 0 && (
        <div className="bg-bg-surface border border-border rounded px-4 py-2 text-[11px] text-text-muted">
          {dropped.length} rule match{dropped.length === 1 ? "" : "es"} filtered
          for platform compatibility (sample: {sampleIdentityPlatform})
        </div>
      )}
      <div className="bg-bg-surface border border-border rounded">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            MITRE ATT&amp;CK Capability Heatmap
          </h2>
          <div className="flex items-center gap-2 text-[11px] text-text-muted">
            <span>conf:</span>
            <div className="w-24 h-2 rounded-sm" style={{
              background: "linear-gradient(to right, #2a2c33, #ff7b72)",
            }} />
            <span>0 → 1</span>
          </div>
        </div>
        <div className="overflow-x-auto">
          <div
            className="grid"
            style={{
              gridTemplateColumns: `repeat(${ENTERPRISE_TACTICS.length}, minmax(120px, 1fr))`,
              minWidth: ENTERPRISE_TACTICS.length * 120,
            }}
          >
            {grid.map((col) => (
              <div
                key={col.tactic.id}
                className="border-r border-border last:border-r-0 bg-bg-surface"
              >
                <div className="px-2 py-2 border-b border-border">
                  <div className="text-[11px] font-mono text-text-muted">{col.tactic.id}</div>
                  <div className="text-xs font-medium text-text-primary truncate" title={col.tactic.name}>
                    {col.tactic.name}
                  </div>
                </div>
                <div>
                  {Array.from({ length: maxRows }).map((_, ri) => {
                    const cell = col.cells[ri];
                    if (!cell) {
                      return (
                        <div
                          key={ri}
                          className="border-b border-border-light h-10"
                          style={{ background: "transparent" }}
                        />
                      );
                    }
                    const key = `${cell.tactic}:${cell.technique_id}`;
                    const active = selectedKey === key;
                    return (
                      <button
                        key={ri}
                        onClick={() => setSelectedKey(active ? null : key)}
                        className={`block w-full text-left px-2 py-1.5 border-b border-border-light hover:ring-1 hover:ring-accent transition-shadow ${active ? "ring-1 ring-accent" : ""}`}
                        style={{ background: cellColor(cell.confidence) }}
                        title={`${cell.technique_id} ${cell.technique_name} — ${(cell.confidence * 100).toFixed(0)}%`}
                      >
                        <div className="text-[11px] font-mono text-text-primary">
                          {cell.technique_id}
                        </div>
                        <div
                          className="text-[11px] text-text-secondary truncate"
                          title={cell.technique_name}
                        >
                          {cell.technique_name}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {selected && (
        <div className="bg-bg-surface border border-border rounded">
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <div>
              <code className="text-sm font-mono text-status-blue">{selected.technique_id}</code>
              <span className="text-sm text-text-primary ml-2">{selected.technique_name}</span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span className="text-text-muted">{selected.tactic_name}</span>
              <span className="text-text-muted">·</span>
              <span className="text-text-primary font-mono">
                {(selected.confidence * 100).toFixed(0)}%
              </span>
              <button
                onClick={() => setSelectedKey(null)}
                className="ml-2 text-[11px] px-2 py-0.5 border border-border rounded text-text-secondary hover:text-text-primary"
              >
                close
              </button>
            </div>
          </div>
          <div className="p-4 space-y-3">
            {selected.contributing_layers.length > 0 && (
              <div>
                <div className="text-[11px] text-text-muted uppercase tracking-wider mb-1">
                  Contributing layers
                </div>
                <div className="flex flex-wrap gap-1">
                  {selected.contributing_layers.map((l) => (
                    <span
                      key={l}
                      className="text-[11px] px-1.5 py-0.5 rounded bg-bg-active text-text-secondary"
                    >
                      {l}
                    </span>
                  ))}
                </div>
              </div>
            )}
            <div>
              <div className="text-[11px] text-text-muted uppercase tracking-wider mb-1">
                Evidence ({selected.evidence.length})
              </div>
              {selected.evidence.length === 0 ? (
                <div className="text-xs text-text-muted">No evidence quotes recorded.</div>
              ) : (
                <ul className="space-y-1.5">
                  {selected.evidence.map((e, i) => (
                    <li
                      key={i}
                      className="text-sm text-text-secondary border-l-2 border-border-light pl-3 leading-relaxed break-words"
                    >
                      {e}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
