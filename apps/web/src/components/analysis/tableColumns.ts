/**
 * A column that says the same thing on every row is not a column.
 *
 * The NETWORK tab's indicator table carried EVIDENCE = `ev_0006` on all forty
 * rows — the one call the whole table came out of, which its own header
 * already cites — and NOTES = "–" on all forty. Two columns of the reader's
 * horizontal space spent restating one fact and one absence.
 *
 * So a constant column is lifted out of the table and stated once, and an
 * empty one is dropped. The first column is never taken: it is what tells one
 * row from another, and a table whose rows are all the same thing is a fact
 * about the run worth seeing.
 */

/**
 * Whether a cell holds anything.
 *
 * Wider than `reportSections.saysSomething`, which knows the one ASCII `-` the
 * console itself prints: a tool writes its own placeholder, and the NETWORK
 * table's forty empty notes were an en dash.
 */
function holdsSomething(value: string): boolean {
  return value !== "" && !/^[-\u2010-\u2015\u2212]+$/.test(value);
}

export interface NarrowedTable {
  columns: string[];
  rows: string[][];
  /** The columns that were lifted, with the one value each of them held. */
  constants: { column: string; value: string }[];
  /** The columns that held nothing on any row. */
  empty: string[];
}

/** The table with its constant and empty columns taken out. */
export function withoutConstantColumns(columns: string[], rows: string[][]): NarrowedTable {
  if (rows.length < 2 || columns.length < 2) {
    return { columns, rows, constants: [], empty: [] };
  }

  const keep: number[] = [];
  const constants: { column: string; value: string }[] = [];
  const empty: string[] = [];

  for (let i = 0; i < columns.length; i++) {
    const values = rows.map((row) => (row[i] ?? "").trim());
    const first = values[0];
    const same = values.every((value) => value === first);
    if (i > 0 && same && !holdsSomething(first)) {
      empty.push(columns[i]);
      continue;
    }
    if (i > 0 && same) {
      constants.push({ column: columns[i], value: first });
      continue;
    }
    keep.push(i);
  }

  if (constants.length === 0 && empty.length === 0) {
    return { columns, rows, constants: [], empty: [] };
  }
  return {
    columns: keep.map((i) => columns[i]),
    rows: rows.map((row) => keep.map((i) => row[i] ?? "")),
    constants,
    empty,
  };
}
