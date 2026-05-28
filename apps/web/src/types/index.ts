/* ── API / Domain Types ─────────────────────────────── */

export type Verdict = "malicious" | "suspicious" | "benign" | "unknown";
export type JobStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/* ── Auth ────────────────────────────────────────────── */
export interface AuthTokens {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  created_at: string;
}

/* ── Sample ──────────────────────────────────────────── */
export interface Sample {
  id: string;
  sha256: string;
  md5: string | null;
  original_filename: string;
  file_size_bytes: number;
  mime_type: string | null;
  uploaded_at: string;
}

/* ── Job ─────────────────────────────────────────────── */
export interface AnalysisJob {
  id: string;
  sample_id: string;
  status: JobStatus;
  config: Record<string, unknown> | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  error_message: string | null;
}

/* ── Report ──────────────────────────────────────────── */
export interface AnalysisReport {
  id: string;
  job_id: string;
  verdict: Verdict;
  overall_confidence: number;
  malware_category: string | null;
  stix_bundle: Record<string, unknown> | null;
  mitre_techniques: MitreTechnique[] | null;
  agent_reports: Record<string, unknown> | null;
  negotiation_log: Record<string, unknown> | null;
  run_summary: Record<string, unknown> | null;
  agent_findings: AgentFinding[];
  created_at: string;
}

export type AgentFindingStatus = "complete" | "no_data" | "failed" | "timeout";

export interface AgentFinding {
  agent_name: string;
  domain: string;
  claims: unknown[] | null;
  dissent_items: unknown[] | null;
  revision_rounds: number;
  final_confidence: number;
  /* D15+D16: lifecycle status separate from confidence. Legacy rows
   * persisted before the field existed default to ``"complete"`` server-
   * side so this is non-optional on the wire. */
  status: AgentFindingStatus;
  status_reason?: string | null;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tactic_id: string;
  match_count: number;
  sources: string[];
}

/* ── WebSocket Events ────────────────────────────────── */
export type WSEventType =
  | "status_change"
  | "pipeline_started"
  | "agent_progress"
  | "phase_change"
  | "completed"
  | "enrichment_complete"
  | "error"
  | "cancelled"
  | "heartbeat"
  | "pong";

export interface WSEvent {
  type: WSEventType;
  data: Record<string, unknown>;
  ts: string;
}
