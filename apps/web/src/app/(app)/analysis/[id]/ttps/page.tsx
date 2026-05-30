"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { useReport } from "../layout";
import { classifyMatrix, resolveMobileTactic } from "@/lib/mitre-mobile";

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

export default function TTpsTab() {
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
  // for every navigation to the TTPs tab. Fall back to the dedicated /mitre
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

  if (loading) {
    return <div className="p-4 text-sm text-text-secondary">Loading...</div>;
  }

  if (!report && (!job || job.status !== "completed")) {
    return (
      <div className="p-4 text-sm text-text-secondary animate-pulse">
        Analysis in progress...
      </div>
    );
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
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        {report
          ? "No MITRE ATT&CK techniques were mapped for this analysis."
          : "Analysis has not completed yet."}
      </div>
    );
  }

  return (
    <div>
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
          className="h-7 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none w-72"
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
                            className={`inline-block w-4 h-4 rounded-full text-center text-[9px] leading-4 ${SOURCE_COLORS[src] || "bg-text-muted/20 text-text-muted"}`}
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
  );
}
