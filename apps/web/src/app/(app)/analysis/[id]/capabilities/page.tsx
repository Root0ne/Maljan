"use client";

import { useEffect, useState } from "react";

import { useReport } from "../layout";
import { api } from "@/lib/api";

/* Canonical MITRE Enterprise tactic catalogue in kill-chain (matrix) column
   order, with display names. TA0005 (Defense Evasion / Stealth in ATT&CK v19)
   and TA0112 (Defense Impairment, added in v19) are both listed so the columns
   stay matrix-accurate as the bundle updates.

   OS-support scope (2026-06-02): the pipeline supports Windows + Linux only, so
   the capabilities view renders the Enterprise matrix exclusively (Mobile / ICS
   matrices were removed alongside the Android/macOS taxonomy).

   NOTE: this is the interim STATIC catalogue. The MITRE auto-update work
   (runtime-refreshed STIX bundle + dynamic taxonomy) replaces it with the live
   bundle's tactic list / order so new ATT&CK releases flow through with no code
   edits. Order + names live here only until that endpoint lands. */
const ENTERPRISE_TACTICS: { id: string; name: string }[] = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0112", name: "Defense Impairment" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
];

const ENTERPRISE_NAME_BY_ID: Record<string, string> = Object.fromEntries(
  ENTERPRISE_TACTICS.map((t) => [t.id, t.name]),
);
const ENTERPRISE_ORDER_BY_ID: Record<string, number> = Object.fromEntries(
  ENTERPRISE_TACTICS.map((t, i) => [t.id, i]),
);

// Sort key: canonical Enterprise order first, then any unrecognized tactic id
// after Enterprise by numeric TA-id so columns stay deterministic.
function tacticOrder(id: string): number {
  if (id in ENTERPRISE_ORDER_BY_ID) return ENTERPRISE_ORDER_BY_ID[id];
  const n = parseInt(id.replace(/\D/g, ""), 10);
  return 1000 + (Number.isFinite(n) ? n : 9999);
}

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
  // Group a flat technique list into tactic buckets keyed by tactic id.
  const tacticMap = new Map<string, Tactic>();

  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const t = item as Record<string, unknown>;

    const techId = String(t.technique_id ?? t.id ?? "");
    const techName = String(t.technique_name ?? t.name ?? techId);
    const tacticId = String(t.tactic_id ?? t.tactic ?? "TA0000");
    let tacticName = String(t.tactic_name ?? "");
    const sources = Array.isArray(t.sources) ? (t.sources as string[]) : [];
    const matches = Number(t.matches ?? t.match_count ?? 1);

    // Enterprise display name from the canonical catalogue when the mapping
    // only carried the TA-id (TTPMapping has no tactic_name field, so columns
    // would otherwise read "TA0005" instead of "Defense Evasion").
    if (!tacticName || tacticName === tacticId || tacticName === "Unknown Tactic") {
      tacticName = ENTERPRISE_NAME_BY_ID[tacticId] ?? tacticName;
    }
    if (!tacticName) tacticName = tacticId || "Unknown Tactic";

    if (!tacticMap.has(tacticId)) {
      tacticMap.set(tacticId, {
        id: tacticId,
        name: tacticName,
        technique_count: 0,
        techniques: [],
      });
    }

    const tactic = tacticMap.get(tacticId)!;
    // Deduplicate techniques within a tactic, summing match counts.
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

export default function AttackTab() {
  const { report, job, loading } = useReport();
  const [search, setSearch] = useState("");
  const [mitreData, setMitreData] = useState<unknown[] | null>(null);

  // Prefer ttp_mappings from the cached MalwareReport; fall back to the /mitre
  // endpoint only for legacy rows that predate the rich report payload.
  useEffect(() => {
    const cached = report?.malware_report?.ttp_mappings;
    if (cached && cached.length > 0) {
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

  // Columns in canonical Enterprise matrix order.
  const activeTactics = [...tactics].sort((a, b) => tacticOrder(a.id) - tacticOrder(b.id));

  const filteredTactics = activeTactics
    .map((tactic) => ({
      ...tactic,
      techniques: tactic.techniques.filter(
        (tech) =>
          search === "" ||
          tech.id.toLowerCase().includes(search.toLowerCase()) ||
          tech.name.toLowerCase().includes(search.toLowerCase()),
      ),
    }))
    .filter((t) => t.techniques.length > 0);

  if (rawTechniques.length === 0) {
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        No MITRE ATT&amp;CK techniques were mapped for this analysis.
      </div>
    );
  }

  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3 flex-wrap">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          MITRE ATT&amp;CK Matrix (Enterprise)
        </h2>
        <input
          type="text"
          placeholder="Search for technique or subtechnique"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-7 px-3 text-xs bg-bg-deep border border-border rounded text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none w-64"
        />
      </div>

      <div className="p-4">
        {filteredTactics.length === 0 ? (
          <div className="p-6 text-center text-xs text-text-muted">
            No techniques match your search.
          </div>
        ) : (
          <div className="flex gap-3 overflow-x-auto pb-2">
            {filteredTactics.map((tactic) => (
              <div key={tactic.id} className="min-w-[200px] max-w-[220px] shrink-0">
                {/* Tactic column header */}
                <div className="bg-bg-active border border-border rounded-t px-3 py-2 border-b-0">
                  <h3 className="text-xs font-medium text-text-primary leading-tight">
                    {tactic.name}
                  </h3>
                  <p className="text-[11px] text-text-muted mt-0.5 font-mono">
                    {tactic.id} &middot; {tactic.techniques.length} technique
                    {tactic.techniques.length === 1 ? "" : "s"}
                  </p>
                </div>

                {/* Technique cards */}
                <div className="space-y-px">
                  {tactic.techniques.map((tech) => (
                    <div
                      key={`${tactic.id}-${tech.id}`}
                      className="bg-bg-elevated border border-border px-3 py-2.5 hover:bg-bg-active transition-colors"
                    >
                      <p className="text-xs text-text-primary font-medium leading-tight mb-1">
                        {tech.name}
                      </p>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-1">
                          <span className="text-[11px] text-text-muted font-mono">{tech.id}</span>
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
                        <span className="text-[11px] text-text-muted">
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
