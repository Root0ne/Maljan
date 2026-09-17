/**
 * What the dynamic analyst concluded, whether or not the sandbox produced
 * anything.
 *
 * The DYNAMIC tab used to render the "not detonated" notice and nothing else
 * whenever the sandbox report was empty — including on runs where the analyst
 * did execute and reasoned its way to a stated position (sandbox evasion,
 * say). That reasoning was in the API's `agent_findings` all along and only
 * the transcript ever showed it, so a run where the analyst worked looked
 * exactly like one where it never started.
 *
 * The tab rule reads this too: it decides whether to offer DYNAMIC for a run
 * with no sandbox report at all, and it must decide it from the same list the
 * page then draws.
 */

import type { AgentFindingDTO } from "@/lib/api";

/** One claim of an analyst's final ISR, as the pipeline records it. */
export interface AnalystClaim {
  claim?: string;
  description?: string;
  confidence?: number;
  evidence_ref?: string | string[];
}

export interface AnalystClaims {
  agent: string;
  claims: AnalystClaim[];
}

/** Every dynamic analyst that said something, with what it said. */
export function dynamicAnalystClaims(
  findings: readonly AgentFindingDTO[] | null | undefined,
): AnalystClaims[] {
  return (findings ?? [])
    .filter(
      (f) =>
        f.domain?.toLowerCase() === "dynamic" ||
        f.agent_name?.toLowerCase().includes("dynamic"),
    )
    .map((f) => ({ agent: f.agent_name, claims: (f.claims ?? []) as AnalystClaim[] }))
    .filter((f) => f.claims.length > 0);
}
