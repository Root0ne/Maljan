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
  /** The characters the tool-output guardrail cut from the answer the model
   *  read; such an entry is also truncated. 0 or absent for an answer stored
   *  whole. */
  chars_dropped?: number;
  /** The function index's exception-directory ranges, by function start; absent elsewhere. */
  function_ranges?: Record<string, string[][]> | null;
  /** The earlier identical call this one was answered from, the label the
   *  recorder parsed out of the arguments, and the run-clock time the call
   *  started at. Absent on rows written before the columns existed. */
  repeated_of?: string | null;
  symbol?: string | null;
  started_at?: number | null;
  created_at: string | null;
  /** Where the tool's declaration lives (`mcp:<server key>`, `provider:<id>`,
   *  `sandbox`, `pack`), what it declared about the answer, the reputation
   *  record, and the operator's pack step, as the entry recorded them. Absent
   *  where the entry carried none and on rows older than the columns. */
  source?: string;
  facts?: Record<string, unknown>;
  reputation?: Record<string, unknown>;
  pack_step?: Record<string, unknown>;
  /** True when `structured` is the server's own structured answer beside a
   *  prose text; absent otherwise. */
  structured_from_server?: true;
  /** The role and console tab the calling agent's definition declared. */
  agent_role?: string;
  agent_tab?: string;
  /** Where the parts of the answer this entry does not keep whole are kept
   *  whole, one reference per part the run shortened, blanked or dropped.
   *  Absent where nothing was taken and on rows older than the column. */
  spilled?: EvidenceObjectRef[];
}

/** One part of an answer kept whole in object storage. `key` is absent and
 *  `error` says why when the upload failed. The bytes are served by
 *  `GET /jobs/{id}/evidence/{entry_id}/objects/{part}`. */
export interface EvidenceObjectRef {
  part: "answer" | "structured_content" | "output" | "structured";
  key?: string;
  bytes?: number;
  sha256?: string;
  error?: string;
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
