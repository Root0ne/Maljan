import type {
  EnrichTriggerResponse,
  IOCListResponse,
  MalwareReport,
  RunSummary,
} from "@/types/malware-report";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

/* ── Shared response types ────────────────────────────── */

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface SampleDTO {
  id: string;
  sha256: string;
  md5: string | null;
  original_filename: string;
  file_size_bytes: number;
  mime_type: string | null;
  uploaded_at: string;
}

export interface JobDTO {
  id: string;
  sample_id: string;
  // BUG-02: readable sample identity so the live view shows a hash/name instead
  // of the opaque sample_id UUID before the report exists.
  sample_sha256?: string | null;
  sample_filename?: string | null;
  status: string;
  config: Record<string, unknown> | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  error_message: string | null;
}

export interface ReportSummaryDTO {
  id: string;
  job_id: string;
  sample_filename: string;
  verdict: string;
  overall_confidence: number;
  malware_category: string | null;
  created_at: string;
  techniques_count: number;
  findings_count: number;
}

export interface AgentFindingDTO {
  agent_name: string;
  domain: string;
  claims: unknown[] | null;
  dissent_items: unknown[] | null;
  revision_rounds: number;
  final_confidence: number;
  // D15+D16 (Wave 3, 2026-05-24): lifecycle status the worker derives
  // from the ISR shape. Defaults server-side to ``"complete"`` for legacy
  // rows so this is non-optional on the wire.
  status: "complete" | "no_data" | "failed" | "timeout";
  status_reason?: string | null;
}

export interface ReportDetailDTO {
  id: string;
  job_id: string;
  verdict: string;
  overall_confidence: number;
  malware_category: string | null;
  stix_bundle: Record<string, unknown> | null;
  mitre_techniques: unknown[] | null;
  agent_reports: Record<string, unknown> | null;
  negotiation_log: Record<string, unknown> | null;
  // Wave 9 (2026-05-29): narrowed from ``Record<string, unknown>`` so
  // the SUMMARY tab can render the FP WARNINGS banner and the
  // CAPABILITIES tab can read platform_filter_summary without casts.
  run_summary: RunSummary | null;
  agent_findings: AgentFindingDTO[];
  malware_report: MalwareReport | null;
  created_at: string;
}

export interface DashboardStatsDTO {
  total_jobs: number;
  total_samples: number;
  jobs_by_status: Record<string, number>;
  verdict_distribution: Record<string, number>;
  avg_duration_seconds: number | null;
}

export interface SystemStatusDTO {
  app_name: string;
  app_version: string;
  mock_mode_allowed: boolean;
  enrichment_enabled: boolean;
  has_virustotal_key: boolean;
  has_abuseipdb_key: boolean;
}

export interface LTMPurgeRequest {
  max_total_techniques?: number;
  require_uncorroborated?: boolean;
  include_analyst_errors?: boolean;
  dry_run?: boolean;
}

export interface LTMPurgeResponse {
  removed: number;
  backend: string;
  dry_run: boolean;
}

export interface AuditLogDTO {
  id: string;
  user_id: string;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown> | null;
  ip_address: string | null;
  created_at: string;
}

export interface ApiKeyDTO {
  id: string;
  user_id: string;
  key_prefix: string;
  name: string;
  expires_at: string | null;
  last_used_at: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface ApiKeyCreateDTO extends ApiKeyDTO {
  raw_key: string;
}

/* ── Runtime schema drift detection ───────────────────────
 *
 * FE-TYPE-SAFETY-DRIFT-01 (audit 2026-05-19): TypeScript types are
 * compile-time only; nothing stops the API from returning a field with
 * the wrong type at runtime. ``assertShape`` walks an "expected" sample
 * once per response and emits a console.warn (with a Sentry breadcrumb
 * hook for future wiring) when the shape diverges. Cheap enough to keep
 * on in production for first-pass alerting; replace with zod when we
 * accept the runtime dep.
 */
type ExpectedShape =
  | "string"
  | "number"
  | "boolean"
  | "string?"
  | "number?"
  | "boolean?"
  | "object?"
  | "array?"
  | "unknown";

const _schemaWarned: Set<string> = new Set();

function _matchesExpected(value: unknown, kind: ExpectedShape): boolean {
  if (kind.endsWith("?") && (value === null || value === undefined)) return true;
  switch (kind.replace("?", "")) {
    case "string":
      return typeof value === "string";
    case "number":
      return typeof value === "number" && !Number.isNaN(value);
    case "boolean":
      return typeof value === "boolean";
    case "object":
      return typeof value === "object" && value !== null && !Array.isArray(value);
    case "array":
      return Array.isArray(value);
    case "unknown":
      return true;
    default:
      return true;
  }
}

function assertShape(
  scope: string,
  value: unknown,
  schema: Record<string, ExpectedShape>
): void {
  if (typeof value !== "object" || value === null) {
    if (_schemaWarned.has(scope)) return;
    _schemaWarned.add(scope);
    // eslint-disable-next-line no-console
    console.warn(
      `[api-schema-drift] ${scope}: expected an object, got ${typeof value}`
    );
    return;
  }
  const obj = value as Record<string, unknown>;
  for (const [key, expectedKind] of Object.entries(schema)) {
    if (!_matchesExpected(obj[key], expectedKind)) {
      const cacheKey = `${scope}#${key}`;
      if (_schemaWarned.has(cacheKey)) continue;
      _schemaWarned.add(cacheKey);
      // eslint-disable-next-line no-console
      console.warn(
        `[api-schema-drift] ${scope}.${key}: expected ${expectedKind}, ` +
          `got ${typeof obj[key]} (value=${JSON.stringify(obj[key])?.slice(0, 80)})`
      );
    }
  }
}

const _JOB_SCHEMA: Record<string, ExpectedShape> = {
  id: "string",
  sample_id: "string",
  status: "string",
  config: "object?",
  created_at: "string",
  started_at: "string?",
  completed_at: "string?",
  duration_seconds: "number?",
  error_message: "string?",
};

const _SYSTEM_STATUS_SCHEMA: Record<string, ExpectedShape> = {
  app_name: "string",
  app_version: "string",
  mock_mode_allowed: "boolean",
  enrichment_enabled: "boolean",
  has_virustotal_key: "boolean",
  has_abuseipdb_key: "boolean",
};

/* ── API Client ───────────────────────────────────────── */

class ApiClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  private getToken(): string | null {
    if (typeof window === "undefined") return null;
    return localStorage.getItem("access_token");
  }

  private async request<T>(
    path: string,
    options: RequestInit = {}
  ): Promise<T> {
    const token = this.getToken();
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers,
    });

    if (res.status === 401 || (res.status === 403 && (await res.clone().json().catch(() => ({})))?.detail === "Not authenticated")) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
      }
      throw new Error("Unauthorized");
    }

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `Request failed: ${res.status}`);
    }

    if (res.status === 204) return {} as T;
    return res.json();
  }

  private async textRequest(
    path: string,
    options: RequestInit = {}
  ): Promise<string> {
    const token = this.getToken();
    const headers: Record<string, string> = {
      ...(options.headers as Record<string, string>),
    };
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers,
    });

    if (res.status === 401) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
      }
      throw new Error("Unauthorized");
    }

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `Request failed: ${res.status}`);
    }

    return res.text();
  }

  private async uploadRequest<T>(
    path: string,
    formData: FormData
  ): Promise<T> {
    const token = this.getToken();
    const headers: Record<string, string> = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const res = await fetch(`${this.baseUrl}${path}`, {
      method: "POST",
      headers,
      body: formData,
    });

    if (res.status === 401 || (res.status === 403 && (await res.clone().json().catch(() => ({})))?.detail === "Not authenticated")) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("access_token");
        localStorage.removeItem("refresh_token");
      }
      throw new Error("Unauthorized");
    }

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || `Upload failed: ${res.status}`);
    }
    return res.json();
  }

  /* ── Auth ──────────────────────────────────────────── */
  login(email: string, password: string) {
    return this.request<{ access_token: string; refresh_token: string }>(
      "/api/v1/auth/login",
      { method: "POST", body: JSON.stringify({ email, password }) }
    );
  }

  register(email: string, password: string, full_name: string) {
    return this.request<{ id: string; email: string }>(
      "/api/v1/auth/register",
      { method: "POST", body: JSON.stringify({ email, password, full_name }) }
    );
  }

  getMe() {
    return this.request<{
      id: string;
      email: string;
      full_name: string;
      role: string;
    }>("/api/v1/auth/me");
  }

  updateMe(body: { full_name?: string; password?: string }) {
    return this.request<{
      id: string;
      email: string;
      full_name: string;
      role: string;
    }>("/api/v1/auth/me", {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  }

  refresh(refreshToken: string) {
    return this.request<{ access_token: string; refresh_token: string }>(
      "/api/v1/auth/refresh",
      { method: "POST", body: JSON.stringify({ refresh_token: refreshToken }) }
    );
  }

  /* ── Dashboard ─────────────────────────────────────── */
  getDashboardStats() {
    return this.request<DashboardStatsDTO>("/api/v1/dashboard/stats");
  }

  /* ── System ────────────────────────────────────────── */
  async getSystemStatus() {
    const data = await this.request<SystemStatusDTO>("/api/v1/system/status");
    assertShape("getSystemStatus", data, _SYSTEM_STATUS_SCHEMA);
    return data;
  }

  ltmPurge(body: LTMPurgeRequest) {
    return this.request<LTMPurgeResponse>("/api/v1/system/ltm/purge", {
      method: "POST",
      body: JSON.stringify(body),
    });
  }

  /* ── Samples ───────────────────────────────────────── */
  getSamples(page = 1, pageSize = 50) {
    return this.request<PaginatedResponse<SampleDTO>>(
      `/api/v1/samples?page=${page}&page_size=${pageSize}`
    );
  }

  getSample(sampleId: string) {
    return this.request<SampleDTO>(`/api/v1/samples/${sampleId}`);
  }

  uploadSample(file: File) {
    const fd = new FormData();
    fd.append("file", file);
    return this.uploadRequest<SampleDTO>(
      "/api/v1/samples/upload",
      fd
    );
  }

  /* ── Jobs ──────────────────────────────────────────── */
  getJobs(page = 1, pageSize = 50, status?: string) {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (status) params.set("status", status);
    return this.request<PaginatedResponse<JobDTO>>(
      `/api/v1/jobs?${params}`
    );
  }

  async getJob(jobId: string) {
    const data = await this.request<JobDTO>(`/api/v1/jobs/${jobId}`);
    assertShape("getJob", data, _JOB_SCHEMA);
    return data;
  }

  createJob(sampleId: string, config?: Record<string, unknown>) {
    return this.request<JobDTO>(
      "/api/v1/jobs",
      { method: "POST", body: JSON.stringify({ sample_id: sampleId, config: config || null }) }
    );
  }

  cancelJob(jobId: string) {
    return this.request<void>(
      `/api/v1/jobs/${jobId}`,
      { method: "DELETE" }
    );
  }

  /**
   * Replay historical pipeline events for a job from the Redis stream.
   * Used by the Live tab on mount to back-fill events that fired before
   * the WebSocket subscribed (audit 2026-05-17, LIVE-01).
   */
  getJobEvents(jobId: string, limit = 500) {
    return this.request<{
      job_id: string;
      events: Array<{
        type: string;
        data: Record<string, unknown>;
        ts: string;
        stream_id: string;
      }>;
      count: number;
    }>(`/api/v1/jobs/${jobId}/events?limit=${limit}`);
  }

  /* ── Reports ───────────────────────────────────────── */
  getReport(reportId: string) {
    return this.request<ReportDetailDTO>(`/api/v1/reports/${reportId}`);
  }

  getReportByJobId(jobId: string) {
    return this.request<ReportDetailDTO>(`/api/v1/reports/job/${jobId}`);
  }

  getReportTimeline(reportId: string) {
    return this.request<Record<string, unknown>>(
      `/api/v1/reports/${reportId}/timeline`
    );
  }

  getReportStix(reportId: string) {
    return this.request<Record<string, unknown>>(
      `/api/v1/reports/${reportId}/stix`
    );
  }

  getReportMitre(reportId: string) {
    return this.request<{ techniques: unknown[] }>(
      `/api/v1/reports/${reportId}/mitre`
    );
  }

  getReports(page = 1, pageSize = 50) {
    return this.request<PaginatedResponse<ReportSummaryDTO>>(
      `/api/v1/reports?page=${page}&page_size=${pageSize}`
    );
  }

  getReportFull(reportId: string) {
    return this.request<MalwareReport>(`/api/v1/reports/${reportId}/full`);
  }

  getReportMarkdown(reportId: string) {
    return this.textRequest(`/api/v1/reports/${reportId}/markdown`);
  }

  getReportIOCs(reportId: string, kind?: string) {
    const qs = kind ? `?kind=${encodeURIComponent(kind)}` : "";
    return this.request<IOCListResponse>(`/api/v1/reports/${reportId}/iocs${qs}`);
  }

  getReportSignature(reportId: string, kind: "yara" | "sigma" | "suricata" | "snort") {
    return this.textRequest(`/api/v1/reports/${reportId}/signatures/${kind}`);
  }

  enrichReport(reportId: string) {
    return this.request<EnrichTriggerResponse>(
      `/api/v1/reports/${reportId}/enrich`,
      { method: "POST" }
    );
  }

  /* ── Audit Logs (admin) ──────────────────────────────── */
  getAuditLogs(page = 1, pageSize = 50, action?: string, userId?: string) {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (action) params.set("action", action);
    if (userId) params.set("user_id", userId);
    return this.request<PaginatedResponse<AuditLogDTO>>(
      `/api/v1/audit/logs?${params}`
    );
  }

  /* ── API Keys ────────────────────────────────────────── */
  getApiKeys(page = 1, pageSize = 50) {
    return this.request<PaginatedResponse<ApiKeyDTO>>(
      `/api/v1/audit/api-keys?page=${page}&page_size=${pageSize}`
    );
  }

  createApiKey(name: string, expiresInDays?: number) {
    return this.request<ApiKeyCreateDTO>(
      "/api/v1/audit/api-keys",
      { method: "POST", body: JSON.stringify({ name, expires_in_days: expiresInDays || null }) }
    );
  }

  revokeApiKey(keyId: string) {
    return this.request<void>(
      `/api/v1/audit/api-keys/${keyId}`,
      { method: "DELETE" }
    );
  }
}

export const api = new ApiClient(API_BASE);
