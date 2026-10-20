import { describe, expect, it } from "vitest";

import { ROWS_PER_STEP, nextStep, visibleRows } from "@/lib/pagedRows";

describe("a long table drawn a step at a time", () => {
  it("draws one step and counts what is left", () => {
    const rows = Array.from({ length: 1234 }, (_, i) => i);
    const { visible, hidden } = visibleRows(rows, ROWS_PER_STEP);
    expect(visible).toHaveLength(ROWS_PER_STEP);
    expect(hidden).toBe(1234 - ROWS_PER_STEP);
  });

  it("reaches every row, a step at a time or all at once", () => {
    const rows = Array.from({ length: 1234 }, (_, i) => i);
    let shown = ROWS_PER_STEP;
    while (shown < rows.length) shown = nextStep(shown, rows.length);
    expect(shown).toBe(1234);
    expect(visibleRows(rows, shown).hidden).toBe(0);
    expect(visibleRows(rows, rows.length).visible).toEqual(rows);
  });

  it("draws a short table whole", () => {
    expect(visibleRows([1, 2, 3], ROWS_PER_STEP)).toEqual({ visible: [1, 2, 3], hidden: 0 });
  });
});
