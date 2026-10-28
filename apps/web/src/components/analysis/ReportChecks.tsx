import type { MalwareReport } from "@/types/malware-report";
import EvidenceChips from "./EvidenceChips";
import {
  claimTechniques,
  claimsNotDiscussed,
  flaggedMark,
  flaggedStatements,
} from "./reportProse";

/* ── What the report's own checks left standing ──────────────────────
 *
 * Two lists the report carries and the console never drew: the report
 * model's sentences a capability or rule-match check asked about and the
 * retry left standing, and the analyst claims in force the body neither cites
 * nor discusses. The exported report prints both; a reader of the console saw
 * the body without either caveat. Nothing is drawn for a report that carries
 * neither, or that was stored before the fields existed.
 */
export default function ReportChecks({ mr }: { mr: MalwareReport }) {
  const flagged = flaggedStatements(mr);
  const undiscussed = claimsNotDiscussed(mr);
  if (flagged.length === 0 && undiscussed.length === 0) return null;
  return (
    <div className="bg-bg-surface border border-border rounded">
      <div className="px-4 py-3 border-b border-border">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          What the report&apos;s checks left standing
        </h2>
      </div>
      <div className="p-4 space-y-4">
        {flagged.length > 0 && (
          <section>
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
              Flagged statements
            </h3>
            <ul className="space-y-1.5">
              {flagged.map((statement, i) => (
                <li key={`${statement.code}-${i}`} className="text-sm text-text-secondary">
                  &ldquo;{statement.sentence}&rdquo;
                  <span className="ml-2 text-[10px] italic text-status-orange">
                    ({flaggedMark(statement)})
                  </span>
                </li>
              ))}
            </ul>
          </section>
        )}
        {undiscussed.length > 0 && (
          <section>
            <h3 className="text-[11px] uppercase tracking-wider text-text-muted mb-1.5">
              Claims the report does not discuss
            </h3>
            <ul className="space-y-1.5">
              {undiscussed.map((claim) => {
                const techniques = claimTechniques(claim);
                return (
                  <li
                    key={`${claim.agent}-${claim.claim_number}`}
                    className="text-sm text-text-secondary"
                  >
                    <span className="text-text-primary font-medium">
                      {claim.agent} #{claim.claim_number}
                    </span>{" "}
                    {techniques && (
                      <span className="text-[11px] text-text-muted">({techniques}) </span>
                    )}
                    {claim.claim}
                    {(claim.missing ?? []).length > 0 && (
                      <span className="ml-2 text-[11px] text-text-muted">
                        not named in the body: {(claim.missing ?? []).join(", ")}
                      </span>
                    )}
                    {claim.evidence_ref && (
                      <EvidenceChips ids={[claim.evidence_ref]} className="ml-2" />
                    )}
                  </li>
                );
              })}
            </ul>
          </section>
        )}
      </div>
    </div>
  );
}
