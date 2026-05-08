"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { useReport } from "../layout";

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
    const tacticId = String(t.tactic_id ?? t.tactic ?? "TA0000");
    const tacticName = String(t.tactic_name ?? t.tactic ?? "Unknown Tactic");
    const sources = Array.isArray(t.sources) ? (t.sources as string[]) : [];
    const matches = Number(t.matches ?? t.match_count ?? 1);

    if (!tacticMap.has(tacticId)) {
      tacticMap.set(tacticId, {
        id: tacticId,
        name: tacticName,
        technique_count: 0,
        techniques: [],
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

  useEffect(() => {
    if (report?.id) {
      api.getReportMitre(report.id)
        .then((data) => setMitreData(data.techniques))
        .catch(() => {});
    }
  }, [report?.id]);

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

  const totalTechniques = tactics.reduce((s, t) => s + t.techniques.length, 0);

  const filteredTactics = tactics.map((tactic) => ({
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
          <button className="px-3 py-1.5 text-xs bg-bg-active text-text-primary border-r border-border">
            Enterprise ({totalTechniques})
          </button>
          <button className="px-3 py-1.5 text-xs text-text-muted hover:text-text-primary">
            Mobile (0)
          </button>
          <button className="px-3 py-1.5 text-xs text-text-muted hover:text-text-primary">
            ICS (0)
          </button>
        </div>
        <input
          type="text"
          placeholder="Search for technique or subtechnique"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-7 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-muted focus:border-accent focus:outline-none w-72"
        />
        <div className="ml-auto flex gap-2">
          <button className="px-3 py-1.5 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted transition-colors">
            Download TTPs
          </button>
        </div>
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
