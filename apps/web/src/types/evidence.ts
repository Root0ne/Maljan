/**
 * The evidence ledger: one entry per tool call a job made.
 *
 * `entry_id` is the citation string ("ev_0007") the report's sections and the
 * agents' findings refer to, so a reader can resolve a claim back to the call
 * that produced it. `structured` is the tool's own JSON when it returned JSON,
 * and `output` the trimmed text either way — empty when the entry lost its
 * output to the per-agent byte budget.
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
  output: string;
  structured: unknown | null;
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
