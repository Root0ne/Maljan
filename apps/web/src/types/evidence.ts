/**
 * The evidence ledger: one entry per tool call a job made.
 *
 * `entry_id` is the citation string ("ev_0007") the report's sections and the
 * agents' findings refer to, so a reader can resolve a claim back to the call
 * that produced it. `structured` is the tool's own JSON when it returned JSON,
 * and `output` the trimmed text either way. An empty `output` is not one
 * thing: a call that lost its result to the per-agent byte budget says so
 * with `truncated`, and a call that failed carries `error`. Only the flag
 * names the budget.
 */

export interface EvidenceEntry {
  id: string;
  entry_id: string;
  stage: string;
  agent: string;
  server: string | null;
  tool: string;
  ok: boolean;
  /** The failure text when `ok` is false, and what the tool said would make
   *  the next call succeed, when it said. Absent on rows written before the
   *  two columns existed. */
  error?: string | null;
  remediation?: string | null;
  duration_ms: number;
  seq: number;
  args: Record<string, unknown> | null;
  /** True when the model's arguments were truncated and were closed off
   *  before the call ran; `args_raw` is what it wrote. */
  args_repaired?: boolean;
  args_raw?: string | null;
  /** The model whose turn asked for this call, as `provider/model`. Absent
   *  where nothing named it, including every row written before the column. */
  model?: string | null;
  output: string;
  structured: unknown | null;
  /** True when the output was dropped to keep the agent inside its byte
   *  budget. Absent on rows written before the column existed, where the
   *  reason an output is empty is simply not recorded. */
  truncated?: boolean;
  /** The earlier identical call this one was answered from, the label the
   *  recorder parsed out of the arguments, and the run-clock time the call
   *  started at. Absent on rows written before the columns existed. */
  repeated_of?: string | null;
  symbol?: string | null;
  started_at?: number | null;
  created_at: string | null;
}

export interface EvidenceListResponse {
  job_id: string;
  entries: EvidenceEntry[];
  total: number;
  page: number;
  page_size: number;
}

/** Narrowing filters the evidence endpoint accepts. */
export interface EvidenceQuery {
  agent?: string;
  tool?: string;
  stage?: string;
  page?: number;
  pageSize?: number;
}
