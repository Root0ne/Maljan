"use client";

import { useEffect, useMemo, useState } from "react";

import { useReport } from "../layout";
import { api } from "@/lib/api";
import { classifyMatrix, resolveMobileTactic } from "@/lib/mitre-mobile";
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

interface CellPaint {
  bg: string;
  fg: string;
  sub: string;
}

// Lerp dim-grey → status-red by confidence, then choose a READABLE text colour
// for that fill. The bright pink-red end (#ff7b72) is light, so the old light
// ramp (#e6edf3 / #9aa4af) sat light-on-light and was unreadable; high-confidence
// cells now get near-black text, dim cells keep the light ramp. The text colour
// is picked by comparing WCAG contrast of near-black vs the light ramp against
// the computed fill luminance.
function cellPaint(confidence: number): CellPaint {
  if (confidence <= 0) {
    return { bg: "#1f2126", fg: "var(--text-primary)", sub: "var(--text-secondary)" };
  }
  const c = Math.min(1, Math.max(0, confidence));
  // base #2a2c33 → #ff7b72 (new --status-red), simple lerp on RGB
  const start = { r: 42, g: 44, b: 51 };
  const end = { r: 255, g: 123, b: 114 };
  const r = Math.round(start.r + (end.r - start.r) * c);
  const g = Math.round(start.g + (end.g - start.g) * c);
  const b = Math.round(start.b + (end.b - start.b) * c);
  const bg = `rgb(${r}, ${g}, ${b})`;
  const lin = (v: number) => {
    const s = v / 255;
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  const L = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
  const darkText = (L + 0.05) / 0.05 >= 1.05 / (L + 0.05);
  return darkText
    ? { bg, fg: "#0d1117", sub: "rgba(13, 17, 23, 0.8)" }
    : { bg, fg: "var(--text-primary)", sub: "var(--text-secondary)" };
}

/* ── ATT&CK capability heatmap (capability_matrix, confidence-graded) ── */
function CapabilityHeatmap() {
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
                    const paint = cellPaint(cell.confidence);
                    return (
                      <button
                        key={ri}
                        onClick={() => setSelectedKey(active ? null : key)}
                        className={`block w-full text-left px-2 py-1.5 border-b border-border-light hover:ring-1 hover:ring-accent transition-shadow ${active ? "ring-1 ring-accent" : ""}`}
                        style={{ background: paint.bg }}
                        title={`${cell.technique_id} ${cell.technique_name} — ${(cell.confidence * 100).toFixed(0)}%`}
                      >
                        <div className="text-[11px] font-mono" style={{ color: paint.fg }}>
                          {cell.technique_id}
                        </div>
                        <div
                          className="text-[11px] truncate"
                          style={{ color: paint.sub }}
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

/* ── Technique browser (ttp_mappings, searchable, multi-matrix) ──────── */
interface Technique {
  id: string;
  name: string;
  matches: number;
  sources: string[];
}

interface Tactic {
  id: string;
  name: string;
  technique_count: number;
  techniques: Technique[];
  matrix: "enterprise" | "mobile" | "ics" | "unknown";
}

const SOURCE_COLORS: Record<string, string> = {
  Static: "bg-status-purple/20 text-status-purple",
  Dynamic: "bg-status-blue/20 text-status-blue",
  Network: "bg-status-orange/20 text-status-orange",
  Code: "bg-status-green/20 text-status-green",
  "Threat Intel": "bg-status-red/20 text-status-red",
};

function parseTechniques(raw: unknown[]): Tactic[] {
  // Group flat technique list into tactic buckets
  const tacticMap = new Map<string, Tactic>();

  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const t = item as Record<string, unknown>;

    const techId = String(t.technique_id ?? t.id ?? "");
    const techName = String(t.technique_name ?? t.name ?? techId);
    let tacticId = String(t.tactic_id ?? t.tactic ?? "TA0000");
    let tacticName = String(t.tactic_name ?? t.tactic ?? "Unknown Tactic");
    const sources = Array.isArray(t.sources) ? (t.sources as string[]) : [];
    const matches = Number(t.matches ?? t.match_count ?? 1);

    // Wave 10 W10-TTP-02 (2026-05-30): Mobile ATT&CK fallback. When the
    // pipeline emits ``TA0000 / Unknown Tactic`` (cascade and sandbox-CTI
    // sources frequently leave the tactic blank for Mobile techniques)
    // resolve the parent technique ID against the curated Mobile map.
    // Caps the matrix attribution so the rendering layer can group + tag
    // appropriately. Failure to resolve leaves the "Unknown" fallback —
    // better honest than misclassified.
    const matrix = classifyMatrix(techId);
    if (tacticId === "TA0000" || tacticName === "Unknown Tactic" || !tacticName) {
      const mobile = resolveMobileTactic(techId);
      if (mobile) {
        tacticId = mobile.id;
        tacticName = mobile.name;
      }
    }

    if (!tacticMap.has(tacticId)) {
      tacticMap.set(tacticId, {
        id: tacticId,
        name: tacticName,
        technique_count: 0,
        techniques: [],
        matrix,
      });
    }

    const tactic = tacticMap.get(tacticId)!;
    // Deduplicate techniques within a tactic
    const existing = tactic.techniques.find((x) => x.id === techId);
    if (existing) {
      existing.matches += matches;
    } else {
      tactic.techniques.push({ id: techId, name: techName, matches, sources });
      tactic.technique_count++;
    }
  }

  return Array.from(tacticMap.values());
}

function TtpBrowser() {
  const { report, job, loading } = useReport();
  const [search, setSearch] = useState("");
  const [mitreData, setMitreData] = useState<unknown[] | null>(null);
  // Wave 10 W10-TTP-02 (2026-05-30): activeMatrix MUST be declared
  // before the early returns below — React enforces a consistent hook
  // call order across renders, and the original placement after the
  // ``if (loading) return ...`` lines tripped the Rules of Hooks
  // violation observed in the first 2026-05-30 smoke test.
  const [activeMatrix, setActiveMatrix] = useState<
    "enterprise" | "mobile" | "ics"
  >("enterprise");

  // Prefer ttp_mappings from the cached MalwareReport — saves one round-trip
  // for every navigation to the ATT&CK tab. Fall back to the dedicated /mitre
  // endpoint only when the rich report is absent (legacy rows pre-Phase 5).
  useEffect(() => {
    const cached = report?.malware_report?.ttp_mappings;
    if (cached && cached.length > 0) {
      // Wave 10 W10-LINT-DEBT-02: legitimate data-fetch initialization —
      // hydrate local state from the cached report fields so we skip the
      // /mitre API round-trip. There is no derived-state alternative here
      // because the cache key (``report?.id``) determines the source of
      // truth and is an effect dep.
      setMitreData(cached as unknown[]);
      return;
    }
    if (report?.id) {
      api
        .getReportMitre(report.id)
        .then((data) => setMitreData(data.techniques))
        .catch(() => {});
    }
  }, [report?.id, report?.malware_report?.ttp_mappings]);

  // The heatmap above already owns the loading / "nothing mapped" states for
  // this tab, so the browser stays quiet (renders nothing) until it has data.
  if (loading) {
    return null;
  }

  if (!report && (!job || job.status !== "completed")) {
    return null;
  }

  const rawTechniques = mitreData ?? (Array.isArray(report?.mitre_techniques)
    ? report.mitre_techniques
    : []);

  const tactics = parseTechniques(rawTechniques);

  // Wave 10 W10-TTP-02 (2026-05-30): split tactics by matrix so the
  // existing "Enterprise (N)" pill grows a sibling "Mobile (M)" pill.
  // Tactics whose matrix is "unknown" stay grouped with Enterprise so
  // they don't disappear from the heatmap when the resolver misses one.
  // Plain computation rather than useMemo — adding a hook here would
  // have to live above the early returns to obey Rules of Hooks, and
  // for the typical 1-10 tactic count the memo cost outweighs the win.
  const tacticsByMatrix = {
    enterprise: tactics.filter(
      (t) => t.matrix === "enterprise" || t.matrix === "unknown",
    ),
    mobile: tactics.filter((t) => t.matrix === "mobile"),
    ics: tactics.filter((t) => t.matrix === "ics"),
  };
  // Auto-pick the first non-empty matrix when the user-selected one
  // is empty — handles the common Android case where activeMatrix
  // defaults to "enterprise" but only "mobile" has techniques.
  const matrixOrder = ["enterprise", "mobile", "ics"] as const;
  const effectiveMatrix =
    tacticsByMatrix[activeMatrix].length > 0
      ? activeMatrix
      : matrixOrder.find((m) => tacticsByMatrix[m].length > 0) ?? activeMatrix;
  const activeTactics = tacticsByMatrix[effectiveMatrix];

  const totalEnterprise = tacticsByMatrix.enterprise.reduce(
    (s, t) => s + t.techniques.length,
    0,
  );
  const totalMobile = tacticsByMatrix.mobile.reduce(
    (s, t) => s + t.techniques.length,
    0,
  );
  const totalICS = tacticsByMatrix.ics.reduce(
    (s, t) => s + t.techniques.length,
    0,
  );

  const filteredTactics = activeTactics.map((tactic) => ({
    ...tactic,
    techniques: tactic.techniques.filter(
      (tech) =>
        search === "" ||
        tech.id.toLowerCase().includes(search.toLowerCase()) ||
        tech.name.toLowerCase().includes(search.toLowerCase())
    ),
  })).filter((t) => t.techniques.length > 0);

  if (rawTechniques.length === 0) {
    return null;
  }

  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          Mapped Techniques
        </h2>
      </div>
      <div className="p-4">
        {/* Controls */}
        <div className="flex items-center gap-3 mb-4">
          <div className="flex border border-border rounded overflow-hidden">
            {(
              [
                ["enterprise", "Enterprise", totalEnterprise],
                ["mobile", "Mobile", totalMobile],
                ["ics", "ICS", totalICS],
              ] as const
            )
              .filter(([, , count]) => count > 0)
              .map(([key, label, count], i, arr) => (
                <button
                  key={key}
                  onClick={() => setActiveMatrix(key)}
                  className={`px-3 py-1.5 text-xs ${
                    effectiveMatrix === key
                      ? "bg-bg-active text-text-primary"
                      : "bg-bg-surface text-text-secondary hover:text-text-primary"
                  } ${i < arr.length - 1 ? "border-r border-border" : ""}`}
                >
                  {label} ({count})
                </button>
              ))}
          </div>
          <input
            type="text"
            placeholder="Search for technique or subtechnique"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-7 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none w-72"
          />
        </div>

        {filteredTactics.length === 0 ? (
          <div className="p-6 text-center text-xs text-text-muted">
            No techniques match your search.
          </div>
        ) : (
          <div className="flex gap-3 overflow-x-auto pb-4">
            {filteredTactics.map((tactic) => (
              <div key={tactic.id} className="min-w-[200px] max-w-[220px] shrink-0">
                {/* Tactic Header */}
                <div className="bg-bg-surface border border-border rounded-t px-3 py-2 border-b-0">
                  <h3 className="text-xs font-medium text-text-primary">{tactic.name}</h3>
                  <p className="text-xs text-text-muted">
                    {tactic.id} | {tactic.technique_count} Techniques
                  </p>
                </div>

                {/* Technique Cards */}
                <div className="space-y-px">
                  {tactic.techniques.map((tech) => (
                    <div
                      key={`${tactic.id}-${tech.id}`}
                      className="bg-bg-elevated border border-border px-3 py-2.5 hover:bg-bg-active transition-colors cursor-pointer"
                    >
                      <div className="flex items-start justify-between mb-1">
                        <p className="text-xs text-text-primary font-medium leading-tight pr-2">
                          {tech.name}
                        </p>
                      </div>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1">
                          <span className="text-xs text-text-muted font-mono">{tech.id}</span>
                          {tech.sources.map((src) => (
                            <span
                              key={src}
                              className={`inline-block w-4 h-4 rounded-full text-center text-[11px] leading-4 ${SOURCE_COLORS[src] || "bg-text-muted/20 text-text-muted"}`}
                              title={src}
                            >
                              {src[0]}
                            </span>
                          ))}
                        </div>
                        <span className="text-xs text-text-muted">
                          {tech.matches} match{tech.matches !== 1 ? "es" : ""}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Merged ATT&CK tab: confidence heatmap + searchable technique browser.
   Was two separate nav tabs (ATT&CK + TTPS) that showed the same MITRE
   mapping in two forms; unified into one tab so the menu has a single
   ATT&CK entry. The legacy /ttps route now redirects here. */
export default function AttackTab() {
  return (
    <div className="space-y-4">
      <CapabilityHeatmap />
      <TtpBrowser />
    </div>
  );
}
