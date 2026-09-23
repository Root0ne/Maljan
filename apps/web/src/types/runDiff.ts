/**
 * What `GET /api/v1/reports/diff` answers: two stored runs compared section
 * by section, each row paired by a key the record already carries.
 *
 * `only_in_a` / `only_in_b` are rows the record does not key stably — a key
 * finding's prose, a STIX object with no identifying property, or a key that
 * repeats inside one run. They are listed by run, never paired by guess, and
 * are a different statement from `added` / `removed`.
 */

export type DiffStatus =
  | "added"
  | "removed"
  | "changed"
  | "unchanged"
  | "only_in_a"
  | "only_in_b";

export type DiffValue = string | number | boolean | null | DiffValue[] | { [key: string]: DiffValue };

export interface DiffChange {
  field: string;
  a: DiffValue;
  b: DiffValue;
}

export interface DiffRow {
  key: string;
  label: string;
  status: DiffStatus;
  /** The row's fields as run A's record holds them; null when A has no such row. */
  a: Record<string, DiffValue> | null;
  b: Record<string, DiffValue> | null;
  /** Each field that differs on a paired row, with both values. */
  changes: DiffChange[];
  /** The evidence-ledger ids each run's record cites for this row, read only
   *  from structured id fields; empty when the record holds none. */
  evidence: { a: string[]; b: string[] };
  note: string | null;
}

export interface DiffSection {
  key: string;
  group: string;
  title: string;
  /** The key the rows are paired by, in words. */
  match_key: string;
  /** False when nothing in the section is paired except by exact text. */
  keyed: boolean;
  /** Whether each run's record holds the source this section reads. */
  recorded: { a: boolean; b: boolean };
  counts: Record<DiffStatus, number>;
  rows: DiffRow[];
  notes: string[];
  /** Ids the record cites for the section as a whole rather than for one row
   *  (the rule-match and capability-profile sections). */
  section_evidence: { a: string[]; b: string[] };
}

export interface DiffSide {
  report_id: string;
  job_id: string;
  created_at: string | null;
  sha256: string | null;
  file_name: string | null;
}

export interface RunDiff {
  a: DiffSide;
  b: DiffSide;
  /** Null when either run's SHA-256 is not recorded. */
  same_sample: boolean | null;
  sample_statement: string;
  totals: Record<DiffStatus, number>;
  sections: DiffSection[];
}
