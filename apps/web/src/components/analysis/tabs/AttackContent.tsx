"use client";

import { useEffect, useState } from "react";

import { useReport } from "@/components/analysis/AnalysisContext";
import BasisMark from "@/components/analysis/BasisMark";
import { VOICE_BASIS, VOICE_TEXT, techniqueVoices, type Voice } from "@/components/analysis/overview";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import Drawer from "@/components/ui/Drawer";
import Section from "@/components/ui/Section";
import type { CorroborationRow } from "@/types/malware-report";
import { VIEW_TACTIC, type BehaviourView } from "@/components/analysis/behaviourView";
import {
  associatedBy,
  corroborationLists,
  corroborationSources,
  retiredNote,
  isCorroborated,
  sourceWords,
  supportLabel,
  orderedTactics,
  parseTechniques,
  tacticHeaderCount,
  type Technique,
} from "@/components/analysis/capabilityHeatmap";

const SOURCE_COLORS: Record<string, string> = {
  Static: "bg-status-purple/20 text-status-purple",
  Dynamic: "bg-status-blue/20 text-status-blue",
  Network: "bg-status-orange/20 text-status-orange",
  Code: "bg-status-green/20 text-status-green",
  "Threat Intel": "bg-status-red/20 text-status-red",
};

type Corroboration = Record<string, CorroborationRow | string[]> | null;

/** Above this many techniques the list offers a search. */
const SEARCH_FROM = 10;

/**
 * The ATT&CK techniques the run mapped: a compact list of tactics, each with
 * its techniques as id chips and counts, and the full matrix on request. A
 * technique opens its sources, its corroboration and what the run recorded
 * for it in the side panel. The Behaviour tab's persistence and defence
 * evasion views keep only their tactic.
 */
export default function AttackContent({ view = "all", empty }: { view?: BehaviourView; empty: boolean }) {
  const { report } = useReport();
  /* How each technique is known, the marker every claim on the page carries. */
  const voices = techniqueVoices(report?.malware_report);
  const [search, setSearch] = useState("");
  const [layout, setLayout] = useState<"list" | "matrix">("list");
  const [detail, setDetail] = useState<{ tech: Technique; tactic: string; opener: HTMLElement } | null>(null);
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
          setFetchError(`Could not load the ATT&CK technique mapping: ${getErrorMessage(err)}`),
        );
    }
  }, [report?.id, report?.malware_report?.capability_matrix, report?.malware_report?.ttp_mappings]);

  const rawTechniques = mitreData ?? (Array.isArray(report?.mitre_techniques) ? report.mitre_techniques : []);
  // Columns in canonical Enterprise matrix order.
  const activeTactics = orderedTactics(parseTechniques(rawTechniques));
  const corroboration = (report?.malware_report?.run_summary?.corroboration ?? null) as Corroboration;
  const inView = view === "all" ? activeTactics : activeTactics.filter((t) => t.id === VIEW_TACTIC[view]);
  const total = inView.reduce((n, t) => n + t.techniques.length, 0);
  const q = search.toLowerCase();
  const filteredTactics = inView
    .map((tactic) => ({
      ...tactic,
      techniques: tactic.techniques.filter(
        (tech) => q === "" || tech.id.toLowerCase().includes(q) || tech.name.toLowerCase().includes(q),
      ),
    }))
    .filter((t) => t.techniques.length > 0);

  /* Read off the parsed matrix rather than the raw array, which is the same
   * reading the tab rule makes: rows that parse to no technique are not a
   * mapping, however many of them there are. */
  const nothing = empty || activeTactics.length === 0;

  return (
    <Section
      title="ATT&CK techniques"
      count={nothing ? null : total}
      empty={nothing && !fetchError}
      actions={
        <div role="group" aria-label="How techniques are shown" className="flex gap-1">
          {(["list", "matrix"] as const).map((l) => (
            <button
              key={l}
              type="button"
              aria-pressed={layout === l}
              onClick={() => setLayout(l)}
              className={`rounded border px-2 py-0.5 text-xs ${
                layout === l ? "border-accent text-accent-strong" : "border-border text-text-secondary hover:text-text-primary"
              }`}
            >
              {l === "list" ? "List" : "Matrix"}
            </button>
          ))}
        </div>
      }
    >
      {nothing ? (
        <p className="text-sm text-text-secondary">{fetchError ?? "This run mapped no ATT&CK technique."}</p>
      ) : (
        <div className="space-y-3">
          {total > SEARCH_FROM && (
            <input
              type="text"
              id="attck-technique-search"
              name="attck-technique-search"
              aria-label="Search ATT&CK techniques"
              placeholder="Search for technique or subtechnique"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-7 w-64 max-w-full rounded border border-border bg-bg-deep px-3 text-xs text-text-primary placeholder:text-text-tertiary focus:border-accent focus:outline-none"
            />
          )}
          {inView.length === 0 ? (
            <p className="text-xs text-text-muted">No technique under this tactic.</p>
          ) : filteredTactics.length === 0 ? (
            <p className="text-xs text-text-muted">No techniques match your search.</p>
          ) : layout === "list" ? (
            <ul className="divide-y divide-border-light" aria-label="Techniques by tactic">
              {filteredTactics.map((tactic) => (
                <li key={tactic.id} className="flex flex-col gap-1.5 py-2 sm:flex-row sm:items-start sm:gap-3">
                  <div className="flex shrink-0 items-center gap-2 sm:w-56">
                    <span className="text-sm font-medium text-text-primary">{tactic.name}</span>
                    <span className="rounded bg-bg-active px-1 font-mono text-[11px] text-text-muted">{tactic.id}</span>
                    <span className="text-[11px] text-text-muted">{tactic.techniques.length}</span>
                  </div>
                  <div className="flex min-w-0 flex-wrap gap-1.5">
                    {tactic.techniques.map((tech) => (
                      <button
                        key={`${tactic.id}-${tech.id}`}
                        type="button"
                        onClick={(e) => setDetail({ tech, tactic: tactic.name, opener: e.currentTarget })}
                        className={`inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 text-xs hover:bg-bg-hover ${
                          tech.notPublished || !tech.valid ? "border-dashed border-status-orange" : "border-border"
                        }`}
                      >
                        <span className="font-mono text-[11px] text-status-blue">{tech.id}</span>
                        <span className="text-text-primary">{tech.name}</span>
                        <span className="text-[11px] text-text-muted">×{tech.matches}</span>
                        <span className="sr-only">: {statusWords(tech)}</span>
                      </button>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <div className="flex gap-3 overflow-x-auto pb-2">
              {filteredTactics.map((tactic) => (
                <div key={tactic.id} className="min-w-[200px] max-w-[220px] shrink-0">
                  {/* Tactic column header */}
                  <div className="rounded-t border border-b-0 border-border bg-bg-active px-3 py-2">
                    <h3 className="text-xs font-medium leading-tight text-text-primary">{tactic.name}</h3>
                    <p className="mt-0.5 font-mono text-[11px] text-text-muted">
                      {tactic.id} &middot; {tacticHeaderCount(tactic.techniques)}
                    </p>
                  </div>
                  <div className="space-y-px">
                    {tactic.techniques.map((tech) => (
                      <div
                        key={`${tactic.id}-${tech.id}`}
                        className="border border-border bg-bg-elevated px-3 py-2.5 hover:bg-bg-active"
                      >
                        <p className="mb-1 text-xs font-medium leading-tight text-text-primary">{tech.name}</p>
                        <TechniqueFacts tech={tech} corroboration={corroboration} voice={voices.get(tech.id)} />
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      <Drawer
        open={detail !== null}
        title={detail ? `${detail.tech.id} ${detail.tech.name}` : ""}
        onClose={() => setDetail(null)}
        returnFocusTo={detail?.opener ?? null}
      >
        {detail && (
          <div className="space-y-3 text-sm">
            <p className="text-text-secondary">Tactic: {detail.tactic}</p>
            <TechniqueFacts tech={detail.tech} corroboration={corroboration} voice={voices.get(detail.tech.id)} open />
          </div>
        )}
      </Drawer>
    </Section>
  );
}

/** The status a technique's chip says to a screen reader, and its card prints. */
function statusWords(tech: Technique): string {
  if (!tech.valid) return "not in catalog";
  if (tech.notPublished) return "claimed, not published";
  return supportLabel(tech) || (isCorroborated(tech) ? "corroborated" : "single source");
}

/** Everything the run recorded about one technique: the matrix card's body. */
function TechniqueFacts({
  tech,
  corroboration,
  open = false,
  voice,
}: {
  tech: Technique;
  corroboration: Corroboration;
  open?: boolean;
  /** How the report knows this technique; absent when it does not map it. */
  voice?: Voice;
}) {
  const lists = corroborationLists(corroboration, tech.id);
  return (
    <>
      {voice && (
        <div className="mb-1">
          <BasisMark basis={VOICE_BASIS[voice].basis} label={VOICE_BASIS[voice].label} detail={VOICE_TEXT[voice]} />
        </div>
      )}
      {!tech.valid && (
        <span
          className="mb-1 inline-block rounded border border-dashed border-status-orange px-1.5 py-0.5 text-[10px] text-status-orange"
          title="The ATT&CK catalog has no entry for this id. The analysis kept it after being told, so it is printed and marked rather than deleted."
        >
          not in catalog
        </span>
      )}
      {/* In words, not colour alone: the card says the technique was claimed
          and not published, and the check's own sentence is printed under it. */}
      {tech.notPublished && (
        <div className="mb-1">
          <span className="inline-block rounded border border-dashed border-status-orange px-1.5 py-0.5 text-[10px] text-status-orange">
            claimed, not published
          </span>
          <p className="mt-0.5 text-[11px] leading-snug text-text-muted">{tech.notPublished}</p>
        </div>
      )}
      {tech.note && (
        <p className="mb-1 text-[11px] leading-snug text-text-muted" data-testid="capability-note">
          {tech.note}
        </p>
      )}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-1">
          <span className="font-mono text-[11px] text-text-muted">{tech.id}</span>
          {/* The verdict's own reading is not a source badge. It read the
              analysts, so listing it beside them would show a technique nobody
              observed twice as one two layers agreed on. The backend leaves it
              out of `is_corroborated` for the same reason. */}
          {tech.corroborating.map((src) => (
            <span
              key={src}
              className={`inline-block h-4 w-4 rounded-full text-center text-[11px] leading-4 ${SOURCE_COLORS[src] || "bg-text-muted/20 text-text-muted"}`}
              title={`Supported by the ${src} analysis layer`}
              role="img"
              aria-label={`Supported by the ${src} analysis layer`}
            >
              <span aria-hidden="true">{src[0]}</span>
            </span>
          ))}
        </div>
        <div className="flex items-center gap-2">
          {supportLabel(tech) ? (
            <span
              className="rounded bg-status-orange/10 px-1.5 py-0.5 text-[10px] text-status-orange"
              title={`${supportLabel(tech)}: sources ${sourceWords(tech)}; none of them a sandbox observation, a code listing or a rule match`}
            >
              {supportLabel(tech)}
            </span>
          ) : isCorroborated(tech) ? (
            <span
              className="rounded bg-status-green/10 px-1.5 py-0.5 text-[10px] text-status-green"
              title={`Corroborated: ${tech.corroborating.length} analysis layers (${tech.corroborating.join(", ")})${tech.sourceCount ? `; sources ${sourceWords(tech)}` : ""}`}
            >
              corroborated
            </span>
          ) : (
            <span
              className="rounded bg-text-muted/10 px-1.5 py-0.5 text-[10px] text-text-muted"
              title={tech.sourceCount ? `Not corroborated: ${tech.corroborating.length} analysis layer${tech.corroborating.length === 1 ? "" : "s"}; sources ${sourceWords(tech)}; short of two independent sayers and sources — weigh with caution` : "Only one analysis layer supports this technique — weigh with caution"}
            >
              single source
            </span>
          )}
          <span className="text-[11px] text-text-muted">
            {tech.matches} match{tech.matches !== 1 ? "es" : ""}
          </span>
        </div>
      </div>
      {/* What the run itself recorded for this id, kept apart from the matrix
          so the two can be compared rather than conflated. */}
      {(corroborationSources(corroboration, tech.id).length > 0 || associatedBy(corroboration, tech.id).length > 0) && (
        <details className="mt-1" open={open}>
          <summary className="cursor-pointer text-[11px] text-text-muted">
            Asserted by {lists.asserted_by.length}, claimed by {lists.claimed_by.length}
            {retiredNote(corroboration, tech.id) && (
              <span className="ml-1 text-status-orange">({retiredNote(corroboration, tech.id)})</span>
            )}
          </summary>
          <div className="mt-1 space-y-1">
            <div>
              <span className="text-[11px] text-text-muted">Asserted by</span>
              <ul className="space-y-0.5">
                {lists.asserted_by.length === 0 && <li className="text-[11px] text-text-muted">no deterministic source</li>}
                {lists.asserted_by.map((source) => (
                  <li key={`a-${source}`} className="font-mono text-[11px] text-text-secondary">
                    {source}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <span className="text-[11px] text-text-muted">Claimed by</span>
              <ul className="space-y-0.5">
                {lists.claimed_by.map((source) => (
                  <li key={`c-${source}`} className="font-mono text-[11px] text-text-secondary">
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
    </>
  );
}
