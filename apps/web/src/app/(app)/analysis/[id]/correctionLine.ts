/**
 * The run record's line about correction turns. A report that does not carry
 * the validation block (stored before it existed, or written without it) says
 * so; it is not read as "no producer needed a correction turn", a zero nobody
 * counted.
 */
export function correctionLine(
  validation: { retries?: number | null } | null | undefined,
  countLabel: (n: number, noun: string) => string,
): string {
  if (!validation || typeof validation.retries !== "number") {
    return "This report does not record correction turns.";
  }
  return validation.retries > 0
    ? `${countLabel(validation.retries, "correction turn")} were spent on producers that answered in the wrong shape.`
    : "No producer needed a correction turn.";
}
