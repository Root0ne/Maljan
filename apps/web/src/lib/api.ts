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
  run_summary: Record<string, unknown> | null;
  agent_findings: AgentFindingDTO[];
  created_at: string;
}

export interface DashboardStatsDTO {
  total_jobs: number;
  total_samples: number;
  jobs_by_status: Record<string, number>;
  verdict_distribution: Record<string, number>;
  avg_duration_seconds: number | null;
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
    }>("/api/v1/auth/me");
  }

  /* ── Dashboard ─────────────────────────────────────── */
  getDashboardStats() {
    return this.request<DashboardStatsDTO>("/api/v1/dashboard/stats");
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

  getJob(jobId: string) {
    return this.request<JobDTO>(`/api/v1/jobs/${jobId}`);
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
