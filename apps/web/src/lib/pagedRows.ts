/**
 * Long tables drawn a step at a time, every row still reachable.
 *
 * The static tab drew a sample's sections, exports and export rows whole —
 * a crafted binary with a hundred thousand exports froze the tab drawing
 * them — and cut its imports and strings at a fixed count with no way to see
 * the rest ("Showing first 500 of 12000"). Both are wrong: one hangs the page,
 * the other hides rows. A table now draws one step and offers the next, and
 * "show all" draws the whole table on request, so nothing is withheld; the
 * step only decides how much is drawn before the reader asks for more.
 */

/** How many rows a long table draws before offering more. */
export const ROWS_PER_STEP = 500;

export function visibleRows<T>(
  rows: readonly T[],
  shown: number,
): { visible: readonly T[]; hidden: number } {
  const count = Math.max(0, Math.min(rows.length, shown));
  return { visible: rows.slice(0, count), hidden: rows.length - count };
}

/** The count after one more step, never past the table's end. */
export function nextStep(shown: number, total: number, step: number = ROWS_PER_STEP): number {
  return Math.min(total, Math.max(0, shown) + step);
}
