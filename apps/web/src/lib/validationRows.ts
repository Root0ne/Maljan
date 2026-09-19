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
 */
const EXPORT_DECIDED: ReadonlySet<string> = new Set([
  "stix.malware_object_under_benign",
  "stix.unpublishable_url",
  "stix.unpublishable_domain",
  "stix.unlinked_technique",
]);

export interface ValidationRow {
  agent: string;
  code: string;
  message: string;
}

/** Whether this row records what the export left out rather than what a producer kept. */
export function isExportDecision(code: string): boolean {
  return EXPORT_DECIDED.has(code);
}

/** The one line the Run record draws for an unresolved validation row. */
export function validationRowText(row: ValidationRow): string {
  if (isExportDecision(row.code)) {
    return `the export did not publish ${row.code}: ${row.message}`;
  }
  return `${row.agent} left ${row.code} unfixed: ${row.message}`;
}
