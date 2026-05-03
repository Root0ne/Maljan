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

export interface AgentFinding {
  agent_name: string;
  domain: string;
  claims: unknown[] | null;
  dissent_items: unknown[] | null;
  revision_rounds: number;
  final_confidence: number;
}

export interface YaraMatch {
  rule_name: string;
  ruleset: string;
  source: string;
  match_count: number;
  severity: Severity;
}

export interface SigmaMatch {
  rule_name: string;
  description: string;
  severity: Severity;
  source: string;
}

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tactic_id: string;
  match_count: number;
  sources: string[];
}

export interface NegotiationRound {
  round: number;
  agent: string;
  position: Verdict;
  confidence: number;
  argument: string;
  timestamp?: string;
}

/* ── Dashboard Stats ─────────────────────────────────── */
export interface DashboardStats {
  total_jobs: number;
  total_samples: number;
  jobs_by_status: Record<string, number>;
  verdict_distribution: Record<string, number>;
  avg_duration_seconds: number | null;
}

/* ── WebSocket Events ────────────────────────────────── */
export interface WSEvent {
  type: "agent_started" | "agent_completed" | "round_update" | "confidence_update" | "analysis_complete" | "error" | "heartbeat";
  data: Record<string, unknown>;
  timestamp: string;
}
