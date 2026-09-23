/**
 * What a run's unresolved validation rows say, in words that name who acted.
 *
 * Every row used to be drawn as "{agent} left {code} unfixed", which is true of
 * a producer that was corrected and answered the same way twice, and the
 * opposite of the truth for a row about the export: the judge wrote a malware
 * object beside an assessment calling the sample benign, and the *export*
 * declined to carry it. A reader was told "judge left
 * stix.malware_object_under_benign unfixed", which blames the judge for a
 * decision the pipeline made about the judge's work.
 *
 * The rows carry the judge as their agent because they are about the judge's
 * own objects, and that stays: the code is what says who decided.
 */

/**
 * The codes a row carries when the decision was the export's, not a producer's.
 *
 * Kept as an explicit list rather than a prefix rule on `stix.`: an ungrounded
 * indicator is also a `stix.` code and is genuinely something the judge was
 * asked about and did not fix.
 *
 * `stix.unpublishable_url` and `stix.unpublishable_domain` were one decision
 * under two names — and the second of them covered addresses too, which is not
 * what it is called. The pipeline writes `stix.unpublishable_endpoint` now and
 * puts the kind in the sentence. A run stored before that keeps the row it
 * recorded, so all three are read here as the same decision.
 */
const EXPORT_DECIDED: ReadonlySet<string> = new Set([
  "stix.malware_object_under_benign",
  "stix.unpublishable_endpoint",
  "stix.unpublishable_url",
  "stix.unpublishable_domain",
  "stix.unpublishable_artefact",
  "stix.malformed_hash",
  "stix.unpublishable_observable_type",
  "stix.unlinked_technique",
]);

export interface ValidationRow {
  agent: string;
  code: string;
  message: string;
  /** The platform declined to act on this row: it measured an absence against
   *  evidence it knows is partial, so the producer's object was kept. Absent
   *  on an ordinary row and on a run stored before the flag existed.
   *
   *  A string on the wire: the channel that carries a finding row is a map of
   *  strings on the Python side, so the flag travels as `"true"` and the
   *  absence of the key is the other answer. */
  advisory?: boolean | string;
}

/** Whether the platform declined to act on this row. */
export function isAdvisory(row: { advisory?: boolean | string }): boolean {
  return row.advisory === true || row.advisory === "true";
}

/** Whether this row records what the export left out rather than what a producer kept. */
export function isExportDecision(code: string): boolean {
  return EXPORT_DECIDED.has(code);
}

/** The one line the Run record draws for an unresolved validation row. */
export function validationRowText(row: ValidationRow): string {
  // A note, not an unfixed finding: the platform could not search this run's
  // whole record, so it wrote the row down and dropped nothing for it. Read as
  // "left unfixed" it accused a producer of ignoring a correction it was right
  // to ignore.
  if (isAdvisory(row)) {
    return `noted for ${row.agent}, nothing dropped — ${row.code}: ${row.message}`;
  }
  if (isExportDecision(row.code)) {
    return `the export did not publish ${row.code}: ${row.message}`;
  }
  return `${row.agent} left ${row.code} unfixed: ${row.message}`;
}
