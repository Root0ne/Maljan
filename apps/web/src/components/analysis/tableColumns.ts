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

/** A cell as text: what a tool wrote, and nothing for a cell it left out. */
function cellText(value: unknown): string {
  if (value === null || value === undefined) return "";
  return typeof value === "string" ? value : String(value);
}

/**
 * Every cell of a table under a heading.
 *
 * A table merged from two answers can carry rows wider than its declared
 * columns: the imports table of one run held `Listed by`, `Evidence` and
 * `Library`, and five of its rows a fourth cell, the function, which drew in
 * no column at all. Nothing is guessed about such a cell. A positional one is
 * headed by its position (`Column 4`), the way a table that declares no
 * columns is; a row keyed by name contributes its keys, so the heading is the
 * name the row itself used. A row shorter than the rest is padded, so every
 * cell stays under the heading it belongs to.
 */
export function headedTable(
  columns: readonly string[],
  rows: readonly unknown[],
): { columns: string[]; rows: string[][] } {
  const headings = [...columns];
  const width = rows.reduce<number>(
    (widest, row) => (Array.isArray(row) ? Math.max(widest, row.length) : widest),
    0,
  );
  for (let i = headings.length; i < width; i++) headings.push(`Column ${i + 1}`);
  for (const row of rows) {
    if (row === null || typeof row !== "object" || Array.isArray(row)) continue;
    for (const key of Object.keys(row)) if (!headings.includes(key)) headings.push(key);
  }
  return {
    columns: headings,
    rows: rows.map((row) => {
      if (Array.isArray(row)) return headings.map((_, i) => cellText(row[i]));
      if (row !== null && typeof row === "object") {
        const keyed = row as Record<string, unknown>;
        return headings.map((heading) => cellText(keyed[heading]));
      }
      return headings.map((_, i) => (i === 0 ? cellText(row) : ""));
    }),
  };
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
