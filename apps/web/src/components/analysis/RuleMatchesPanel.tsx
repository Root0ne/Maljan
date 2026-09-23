"use client";

import { useMemo, useState } from "react";
import { ChevronDown } from "lucide-react";
import { useReport } from "@/app/(app)/analysis/[id]/layout";
import { SEVERITY_LADDER, ladderDots, severityRung, severityTone, severityWord } from "@/lib/severity";
import type { EvidenceSection } from "@/types/malware-report";
import EvidenceChips from "./EvidenceChips";
import { orderByLevel, ruleMatches } from "./ruleMatches";

/**
 * The ledger entries a kind's rows were built from, as the chips STATIC's
 * section tables drew before these rows moved here — or, for a section that
 * cites no entry, where it came from. Nothing for rows read from old claims,
 * which cite their entry on the row itself.
 */
function Provenance({ section }: { section: EvidenceSection | null }) {
  if (!section) return null;
  return (
    <span data-rule-provenance={section.key}>
      <EvidenceChips
        ids={section.evidence_ids}
        source={section.evidence_ids.length === 0 ? section.source : undefined}
      />
    </span>
  );
}

/** A stored claim row: the layer never recorded a level. */
const NOT_RECORDED = "level not recorded";
/** A current run's row whose rule declares no level. */
const NO_LEVEL_DECLARED = "no level declared";

/** What a row without a level says, by whether its source records levels. */
function noLevel(recorded: boolean): string {
  return recorded ? NO_LEVEL_DECLARED : NOT_RECORDED;
}

function Section({
  title,
  defaultOpen,
  children,
}: {
  title: string;
  defaultOpen: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded mb-4">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-medium text-text-primary uppercase tracking-wider hover:bg-bg-hover"
      >
        <span>{title}</span>
        <ChevronDown
          size={16}
          aria-hidden="true"
          className={`text-text-muted transition-transform ${open ? "rotate-180" : ""}`}
        />
      </button>
      {open && <div className="border-t border-border">{children}</div>}
    </div>
  );
}

export default function RulesTab() {
  const { report, job, loading } = useReport();

  /* One reading of the run's rule matches, shared with the tab rule that
   * decides whether this panel is reachable at all (`ruleMatches.ts`). */
  const {
    yara: yaraMatches,
    sigma: unsortedSigma,
    yaraSection,
    sigmaSection,
  } = useMemo(
    () => ruleMatches(report?.agent_findings, report?.malware_report?.sections),
    [report?.agent_findings, report?.malware_report?.sections],
  );
  /* By the rule's own level, highest rung first; a row whose level was not
   * recorded takes no part in that order and follows as recorded. */
  const sigmaMatches = useMemo(() => orderByLevel(unsortedSigma), [unsortedSigma]);

  /* The legend counts the rungs the rules declared, and says how many rows
   * recorded none rather than filing them under a rung. */
  const levelCounts = useMemo(
    () =>
      sigmaMatches.reduce(
        (acc, r) => {
          const key = r.level === null ? noLevel(r.recorded) : severityWord(r.level);
          acc[key] = (acc[key] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      ),
    [sigmaMatches],
  );

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

  // The DETECTION tab draws this section only when a rule fired.
  if (yaraMatches.length === 0 && sigmaMatches.length === 0) return null;

  return (
    <div>
      {yaraMatches.length > 0 && (
        <Section title={`YARA Matches (${yaraMatches.length})`} defaultOpen={true}>
          <div className="flex flex-wrap items-center gap-2 bg-status-blue/10 px-4 py-2 border-b border-border">
            <span className="text-xs font-medium text-status-blue uppercase tracking-wider">
              YARA Rules
            </span>
            <Provenance section={yaraSection} />
          </div>
          <div className="divide-y divide-border-light">
            {yaraMatches.map((rule, i) => (
              <div
                key={`${rule.rule_name}-${i}`}
                className="flex items-start gap-3 px-4 py-2.5 hover:bg-bg-hover"
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 text-xs">
                    <span className="text-accent">{rule.rule_name}</span>
                    {rule.pattern_count > 0 && (
                      <>
                        <span className="text-text-muted">·</span>
                        <span className="text-text-secondary">
                          {rule.pattern_count} pattern{rule.pattern_count === 1 ? "" : "s"}
                        </span>
                      </>
                    )}
                    {rule.technique_id && (
                      <>
                        <span className="text-text-muted">·</span>
                        <span className="text-text-secondary font-mono">{rule.technique_id}</span>
                      </>
                    )}
                    {rule.tags && (
                      <>
                        <span className="text-text-muted">·</span>
                        <span className="text-text-secondary">{rule.tags}</span>
                      </>
                    )}
                  </div>
                  {rule.evidence && (
                    <p className="text-xs text-text-secondary mt-0.5 truncate" title={rule.evidence}>
                      {rule.evidence}
                    </p>
                  )}
                </div>
                {/* An old layer's confidence in the match; a current run's
                    row carries none and shows none. */}
                {rule.confidence !== null && (
                  <span className="text-xs text-text-muted shrink-0 font-mono">
                    confidence {rule.confidence.toFixed(2)}
                  </span>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {sigmaMatches.length > 0 && (
        <Section title={`Sigma Matches (${sigmaMatches.length})`} defaultOpen={true}>
          <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2 border-b border-border bg-bg-elevated">
            <span className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-medium text-text-primary uppercase tracking-wider">
                Sigma Rules
              </span>
              <Provenance section={sigmaSection} />
            </span>
            <div className="flex items-center gap-3">
              {/* The ladder's rungs in its order, each some rule declared; a
                  rung at zero says nothing the rows below do not. */}
              <span className="text-xs text-text-muted">Rule level:</span>
              {[...SEVERITY_LADDER, NO_LEVEL_DECLARED, NOT_RECORDED]
                .filter((key) => levelCounts[key])
                .map((key) => (
                  <span key={key} className="flex items-center gap-1 text-xs text-text-secondary">
                    <span>{key}</span>
                    <span className="text-text-muted">({levelCounts[key]})</span>
                  </span>
                ))}
            </div>
          </div>
          <div className="divide-y divide-border-light">
            {sigmaMatches.map((rule, i) => {
              const onLadder = rule.level !== null && severityRung(rule.level) !== null;
              const style = severityTone(rule.level);
              return (
                <div
                  key={`${rule.rule_name}-${i}`}
                  className="flex items-start gap-3 px-4 py-3 hover:bg-bg-hover"
                >
                  <div className="flex items-center gap-1 mt-0.5 shrink-0 w-28" data-rule-level>
                    {/* One dot per rung from Informational up, so Low and
                        Informational differ. A level that is not a rung, and a
                        row that recorded none, draw no dots: there is nothing
                        on the ladder to draw. */}
                    {onLadder && (
                      <div className="flex gap-0.5" aria-hidden="true">
                        {Array.from({ length: ladderDots(rule.level) }).map((_, j) => (
                          <span key={j} className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                        ))}
                      </div>
                    )}
                    {rule.level === null ? (
                      <span className="text-xs text-text-muted">{noLevel(rule.recorded)}</span>
                    ) : (
                      <span className={`text-xs ml-1 ${onLadder ? style.text : "text-text-secondary"}`}>
                        <span className="sr-only">Rule level </span>
                        {severityWord(rule.level)}
                      </span>
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-accent">{rule.rule_name}</p>
                    <div className="flex items-center gap-2 text-xs text-text-secondary mt-0.5">
                      {rule.technique_id && (
                        <span className="font-mono">{rule.technique_id}</span>
                      )}
                      {rule.source && (
                        <>
                          <span className="text-text-muted">·</span>
                          <span>source={rule.source}</span>
                        </>
                      )}
                    </div>
                    {rule.evidence && (
                      <p className="text-xs text-text-muted mt-1 truncate">{rule.evidence}</p>
                    )}
                  </div>
                  {/* An old layer's confidence in the match, from the rule's
                      maturity status: a number, never a severity. A current
                      run's row carries none and shows none. */}
                  {rule.confidence !== null && (
                    <span className="text-xs text-text-muted shrink-0 font-mono">
                      confidence {rule.confidence.toFixed(2)}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </Section>
      )}
    </div>
  );
}
