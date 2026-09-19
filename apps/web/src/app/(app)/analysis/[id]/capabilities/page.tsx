"use client";

import { useEffect, useState } from "react";

import { useReport } from "../layout";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import {
  associatedBy,
  corroborationLists,
  corroborationSources,
  retiredIn,
  isCorroborated,
  orderedTactics,
  parseTechniques,
  tacticHeaderCount,
} from "@/components/analysis/capabilityHeatmap";

const SOURCE_COLORS: Record<string, string> = {
  Static: "bg-status-purple/20 text-status-purple",
  Dynamic: "bg-status-blue/20 text-status-blue",
  Network: "bg-status-orange/20 text-status-orange",
  Code: "bg-status-green/20 text-status-green",
  "Threat Intel": "bg-status-red/20 text-status-red",
};

export default function AttackTab() {
  const { report, job, loading } = useReport();
  const [search, setSearch] = useState("");
  const [mitreData, setMitreData] = useState<unknown[] | null>(null);
  // A failed /mitre fallback
  // rendered as "no techniques mapped", which is a different claim entirely.
  const [fetchError, setFetchError] = useState<string | null>(null);

  // Prefer the capability matrix from the cached MalwareReport: it carries a
  // cell for every technique a producer named, published or not, and a
  // technique the run declined to publish has to be visible as that rather
  // than absent. `ttp_mappings` is the published subset and is the fallback
  // for a report stored before the matrix carried the reason; the /mitre
  // endpoint is the fallback for one stored before either.
  useEffect(() => {
    const cells = report?.malware_report?.capability_matrix;
    if (cells && cells.length > 0) {
      setMitreData(cells as unknown[]);
      return;
    }
    const cached = report?.malware_report?.ttp_mappings;
    if (cached && cached.length > 0) {
      setMitreData(cached as unknown[]);
      return;
    }
    if (report?.id) {
      api
        .getReportMitre(report.id)
        .then((data) => {
          setMitreData(data.techniques);
          setFetchError(null);
        })
        .catch((err: unknown) =>
          setFetchError(
            `Could not load the ATT&CK technique mapping: ${getErrorMessage(err)}`,
          ),
        );
    }
  }, [
    report?.id,
    report?.malware_report?.capability_matrix,
    report?.malware_report?.ttp_mappings,
  ]);

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
  const activeTactics = orderedTactics(tactics);
  const corroboration = report?.malware_report?.run_summary?.corroboration ?? null;

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

  if (activeTactics.length === 0) {
    /* The tab is offered only when the run mapped something, so this is what a
     * direct link to it sees: either the mapping could not be read, which is a
     * different claim from an empty mapping, or the run mapped nothing.
     *
     * Read off the parsed matrix rather than the raw array, which is the same
     * reading the tab rule makes: rows that parse to no technique are not a
     * mapping, however many of them there are. */
    return (
      <div className="p-8 text-center text-sm text-text-secondary">
        {fetchError ?? "This run mapped no ATT&CK technique."}
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
          id="attck-technique-search"
          name="attck-technique-search"
          aria-label="Search ATT&CK techniques"
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
                    {tactic.id} &middot; {tacticHeaderCount(tactic.techniques)}
                  </p>
                </div>

                {/* Technique cards */}
                <div className="space-y-px">
                  {tactic.techniques.map((tech) => {
                    const lists = corroborationLists(corroboration, tech.id);
                    return (
                      <div
                        key={`${tactic.id}-${tech.id}`}
                        className="bg-bg-elevated border border-border px-3 py-2.5 hover:bg-bg-active"
                      >
                        <p className="text-xs text-text-primary font-medium leading-tight mb-1">
                          {tech.name}
                        </p>
                        {!tech.valid && (
                          <span
                            className="inline-block mb-1 text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border border-dashed border-status-orange text-status-orange"
                            title="The ATT&CK catalog has no entry for this id. The producer kept it after being told, so it is printed and marked rather than deleted."
                          >
                            not in catalog
                          </span>
                        )}
                        {/* In words, not colour alone: the card says the
                            technique was claimed and not published, and the
                            check's own sentence is printed under it. */}
                        {tech.notPublished && (
                          <div className="mb-1">
                            <span className="inline-block text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded border border-dashed border-status-orange text-status-orange">
                              claimed, not published
                            </span>
                            <p className="mt-0.5 text-[11px] text-text-muted leading-snug">
                              {tech.notPublished}
                            </p>
                          </div>
                        )}
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-1">
                            <span className="text-[11px] text-text-muted font-mono">{tech.id}</span>
                            {/* The judge is not a source badge. It read the
                                analysts, so listing it beside them would show a
                                technique nobody observed twice as one two layers
                                agreed on. The backend leaves it out of
                                `is_corroborated` for the same reason. */}
                            {tech.corroborating.map((src) => (
                              <span
                                key={src}
                                className={`inline-block w-4 h-4 rounded-full text-center text-[11px] leading-4 ${SOURCE_COLORS[src] || "bg-text-muted/20 text-text-muted"}`}
                                title={`Supported by the ${src} analysis layer`}
                                role="img"
                                aria-label={`Supported by the ${src} analysis layer`}
                              >
                                <span aria-hidden="true">{src[0]}</span>
                              </span>
                            ))}
                          </div>
                          <div className="flex items-center gap-2">
                            {isCorroborated(tech) ? (
                              <span
                                className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-status-green/10 text-status-green"
                                title={`Corroborated across ${tech.corroborating.length} independent analysis layers (${tech.corroborating.join(", ")})`}
                              >
                                corroborated
                              </span>
                            ) : (
                              <span
                                className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-text-muted/10 text-text-muted"
                                title="Only one analysis layer supports this technique — weigh with caution"
                              >
                                single source
                              </span>
                            )}
                            <span className="text-[11px] text-text-muted">
                              {tech.matches} match{tech.matches !== 1 ? "es" : ""}
                            </span>
                          </div>
                        </div>
                        {/* What the run itself recorded for this id, kept apart
                            from the matrix so the two can be compared rather
                            than conflated. */}
                        {(corroborationSources(corroboration, tech.id).length > 0 ||
                          associatedBy(corroboration, tech.id).length > 0) && (
                          <details className="mt-1">
                            <summary className="text-[10px] uppercase tracking-wider text-text-muted cursor-pointer">
                              Asserted by {lists.asserted_by.length}
                              , claimed by {lists.claimed_by.length}
                              {retiredIn(corroboration, tech.id) && (
                                <span className="ml-1 normal-case tracking-normal text-status-orange">
                                  (retired in ATT&amp;CK {retiredIn(corroboration, tech.id)})
                                </span>
                              )}
                            </summary>
                            <div className="mt-1 space-y-1">
                              <div>
                                <span className="text-[10px] uppercase tracking-wider text-text-muted">
                                  Asserted by
                                </span>
                                <ul className="space-y-0.5">
                                  {lists.asserted_by.length === 0 && (
                                    <li className="text-[11px] text-text-muted">no deterministic source</li>
                                  )}
                                  {lists.asserted_by.map((source) => (
                                    <li key={`a-${source}`} className="text-[11px] font-mono text-text-secondary">
                                      {source}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                              <div>
                                <span className="text-[10px] uppercase tracking-wider text-text-muted">
                                  Claimed by
                                </span>
                                <ul className="space-y-0.5">
                                  {lists.claimed_by.map((source) => (
                                    <li key={`c-${source}`} className="text-[11px] font-mono text-text-secondary">
                                      {source}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                              {associatedBy(corroboration, tech.id).length > 0 && (
                                <div className="text-[11px] text-text-muted">
                                  Catalogue association (reference, not a source):{" "}
                                  <span className="font-mono">{associatedBy(corroboration, tech.id).join(", ")}</span>
                                </div>
                              )}
                            </div>
                          </details>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
