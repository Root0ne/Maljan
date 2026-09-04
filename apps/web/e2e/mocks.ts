import type { Page, Route, WebSocketRoute } from "@playwright/test";

/**
 * The whole API surface the E2E suite is allowed to touch — and a trap for
 * everything it is not.
 *
 * ## Why this file exists
 *
 * The mocks used to live in `fixtures.ts` and covered five endpoints. The pages
 * under test call rather more than five, and `lib/api.ts` used to default to
 * `http://127.0.0.1:8000`, so on any machine running the dev backend every
 * uncovered call quietly reached the real API and returned real data. Tests
 * asserting on live database rows looked exactly like tests asserting on
 * mocks — until the backend was down, or the data changed.
 *
 * Two things close that. `playwright.config.ts` points NEXT_PUBLIC_API_URL at
 * the Next server's own origin, so a stray call can no longer leave the test
 * process's reach; and the catch-all below turns it into a named failure
 * instead of a silent 501 nobody reads.
 *
 * ## Route precedence
 *
 * Playwright uses the route registered **last** among those that match, so the
 * catch-all is registered **first** and everything after it — the defaults
 * here, then any `page.route(...)` a spec adds — takes precedence. Verified
 * empirically rather than assumed: with the catch-all first, its handler is not
 * merely out-voted, it is never invoked at all.
 *
 * Two glob details, also measured rather than inferred, because both look like
 * they should collide and do not. A pattern is matched against the full URL
 * *including the query string*, so a pattern ending in `jobs` matches only the
 * bare collection path and leaves the one ending in `jobs?` + wildcard to serve
 * the paginated list. And a single `*` never crosses a slash, so a pattern
 * ending `jobs/` + `*` cannot swallow `jobs/{id}/events`.
 *
 * ## Adding an endpoint
 *
 * Add it to `installApiMocks` if every spec wants the same answer; override it
 * with `page.route(...)` inside the spec if only one does. Do not reach for the
 * real backend — if a test needs live data, it is an integration test, not this.
 */

/** URLs that reached the catch-all, per page. Read by `assertNoUnmockedCalls`. */
const unmockedByPage = new WeakMap<Page, string[]>();

const JSON_HEADERS = { "content-type": "application/json" };

function json(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
}

/* ── Default payloads ───────────────────────────────────
 * Shapes follow the DTOs in lib/api.ts. `getJob` and `getSystemStatus` assert
 * their shape at runtime and `console.warn` on drift, so a hand-waved mock
 * turns every run into a wall of [api-schema-drift] noise — these match
 * `_JOB_SCHEMA` and `_SYSTEM_STATUS_SCHEMA` field for field. */

export const MOCK_USER = {
  id: "user-1",
  email: "test@example.com",
  full_name: "Test User",
  role: "analyst",
};

export const MOCK_JOB_SUMMARY = {
  id: "job-1",
  sample_id: "sample-1",
  sample_filename: "invoice_scan.exe",
  status: "completed",
  verdict: "Malware",
  overall_confidence: 0.93,
  created_at: "2026-07-26T10:00:00Z",
  completed_at: "2026-07-26T10:12:00Z",
  duration_seconds: 720,
};

/** Matches `_JOB_SCHEMA`. Defaults to `running`: a spec that cares about a
 *  terminal state says so, and a spec that just needs the page to mount gets
 *  the live path, which is the one with the moving parts. */
export const MOCK_JOB_DETAIL = {
  id: "00000000-0000-0000-0000-000000000000",
  sample_id: "sample-1",
  sample_filename: "invoice_scan.exe",
  status: "running",
  config: null,
  created_at: "2026-07-26T10:00:00Z",
  started_at: "2026-07-26T10:00:05Z",
  completed_at: null,
  duration_seconds: null,
  error_message: null,
};

export const MOCK_DASHBOARD_STATS = {
  total_jobs: 42,
  total_samples: 15,
  jobs_by_status: {
    pending: 5,
    running: 2,
    completed: 30,
    failed: 3,
    cancelled: 2,
  },
  verdict_distribution: {
    Malware: 25,
    Benign: 3,
    Suspicious: 2,
  },
  avg_duration_seconds: 120,
};

/** Matches `_SYSTEM_STATUS_SCHEMA`. */
export const MOCK_SYSTEM_STATUS = {
  app_name: "Maljan",
  app_version: "0.1.0",
  mock_mode_allowed: false,
  enrichment_enabled: true,
  has_virustotal_key: true,
  has_abuseipdb_key: false,
};

export const MOCK_SAMPLE = {
  id: "sample-1",
  sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  md5: "5d41402abc4b2a76b9719d911017c592",
  original_filename: "invoice_scan.exe",
  file_size_bytes: 204800,
  mime_type: "application/x-dosexec",
  uploaded_at: "2026-07-26T10:00:00Z",
};

export const MOCK_SANDBOX_REPORT = {
  id: "sandbox-report-1",
  format: "cape2",
  task_id: "1000",
  size_bytes: 512,
  sample_sha256_match: true,
  warning: null,
  uploaded_at: "2026-07-26T10:05:00Z",
};

export const MOCK_REPORT_SUMMARY = {
  id: "report-1",
  job_id: "job-1",
  sample_filename: "invoice_scan.exe",
  // Raw backend spelling: the UI must render "Malicious".
  verdict: "Malware",
  overall_confidence: 0.93,
  malware_category: "trojan",
  created_at: "2026-07-26T10:00:00Z",
  techniques_count: 7,
  findings_count: 12,
};

export const MOCK_AUDIT_LOG = {
  id: "log-1",
  user_id: "user-1",
  action: "job.create",
  resource_type: "job",
  resource_id: "job-1abc2def-0000-0000-0000-000000000000",
  details: null,
  ip_address: "10.0.0.5",
  created_at: "2026-07-26T10:00:00Z",
};

export const MOCK_API_KEY = {
  id: "key-1",
  user_id: "user-1",
  key_prefix: "mlj_a1b2",
  name: "CI/CD integration",
  expires_at: null,
  last_used_at: null,
  is_active: true,
  created_at: "2026-07-26T10:00:00Z",
  updated_at: "2026-07-26T10:00:00Z",
};

/**
 * Matches `apps/api/app/schemas/settings.py::SchemaResponse` /
 * `apps/web/src/types/settings.ts::SettingsSchema`. Three groups: three field
 * shapes in "negotiation" (plain int, a second int pre-seeded with a `"ui"`
 * source in `MOCK_SETTINGS_VALUES` below so per-row / group reset visibility
 * — shown only for a `"ui"`-sourced value — has something to contrast
 * against the `"default"`/`"env"` rows that must not show it, and a `list`
 * field defaulting to `[]` for `ListWidget` coverage), one secret in
 * "providers", and "sandbox" — a provider selector (`order: -1`) plus two
 * `applies_when`-gated fields, covering conditional visibility.
 */
export const MOCK_SETTINGS_SCHEMA = {
  secrets_available: true,
  groups: [
    {
      key: "negotiation",
      title: "Negotiation",
      entries: [
        {
          key: "core.negotiation.max_iterations",
          namespace: "core",
          path: "negotiation.max_iterations",
          type: "int",
          default: 5,
          nullable: false,
          choices: null,
          minimum: 1,
          maximum: null,
          secret: false,
          group: "negotiation",
          title: "Max iterations",
          description: "Hard ceiling on negotiation rounds.",
          applies: "next_job",
          editable: true,
          reason: null,
          probe: null,
          applies_when: null,
          order: 0,
        },
        {
          key: "core.negotiation.retry_delay",
          namespace: "core",
          path: "negotiation.retry_delay",
          type: "int",
          default: 2,
          nullable: false,
          choices: null,
          minimum: 0,
          maximum: null,
          secret: false,
          group: "negotiation",
          title: "Retry delay seconds",
          description: "Delay between negotiation retries.",
          applies: "next_job",
          editable: true,
          reason: null,
          probe: null,
          applies_when: null,
          order: 0,
        },
        {
          key: "core.negotiation.blocked_hosts",
          namespace: "core",
          path: "negotiation.blocked_hosts",
          type: "list",
          default: [],
          nullable: false,
          choices: null,
          minimum: null,
          maximum: null,
          secret: false,
          group: "negotiation",
          title: "Blocked hosts",
          description: "Hostnames the negotiator refuses to contact.",
          applies: "next_job",
          editable: true,
          reason: null,
          probe: null,
          applies_when: null,
          order: 0,
        },
      ],
    },
    {
      key: "providers",
      title: "Providers",
      entries: [
        {
          key: "core.llm.openai.api_key",
          namespace: "core",
          path: "llm.openai.api_key",
          type: "secret",
          default: null,
          nullable: true,
          choices: null,
          minimum: null,
          maximum: null,
          secret: true,
          group: "providers",
          title: "OpenAI-compatible API key",
          description: "Bearer token for the OpenAI-compatible endpoint.",
          applies: "next_job",
          editable: true,
          reason: null,
          probe: "llm",
          applies_when: null,
          order: 0,
        },
      ],
    },
    // Task A21: `applies_when` drives conditional visibility; `order: -1`
    // puts the selector first.
    {
      key: "sandbox",
      title: "Sandbox provider",
      entries: [
        {
          key: "core.sandbox.provider", namespace: "core", path: "sandbox.provider",
          type: "enum", default: "mock", nullable: false,
          choices: ["mock", "cape2", "upload", "triage"],
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Sandbox provider", description: "Which sandbox produces the dynamic evidence.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1,
        },
        {
          key: "core.sandbox.cape2.base_url", namespace: "core", path: "sandbox.cape2.base_url",
          type: "str", default: "http://localhost:8000", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "CAPEv2 base URL", description: "Base URL of the CAPEv2 REST API.",
          applies: "next_job", editable: true, reason: null, probe: "cape2",
          applies_when: { "core.sandbox.provider": ["cape2"] }, order: 0,
        },
        {
          key: "core.sandbox.triage.base_url", namespace: "core", path: "sandbox.triage.base_url",
          type: "str", default: "https://tria.ge/api/v0", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Triage API base URL", description: "Hatching Triage cloud API root.",
          applies: "next_job", editable: true, reason: null, probe: "triage",
          applies_when: { "core.sandbox.provider": ["triage"] }, order: 0,
        },
      ],
    },
  ],
};

export const MOCK_SETTINGS_VALUES = {
  values: {
    "core.negotiation.max_iterations": {
      value: 5,
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.negotiation.retry_delay": {
      value: 10,
      is_set: null,
      hint: null,
      source: "ui",
      updated_at: "2026-08-01T00:00:00Z",
      updated_by: "user-1",
    },
    "core.negotiation.blocked_hosts": {
      value: [],
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.llm.openai.api_key": {
      value: null,
      is_set: true,
      hint: "1234",
      source: "env",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.provider": {
      value: "cape2",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.cape2.base_url": {
      value: "http://localhost:8000",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.triage.base_url": {
      value: "https://tria.ge/api/v0",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
  },
};

export interface MockOptions {
  /**
   * Handler for `**​/ws/analysis/**`. The default accepts the connection and
   * stays silent, which is enough for pages that merely mount `useWebSocket`.
   * Pass `null` to leave the socket unrouted so the spec can install its own —
   * explicit, rather than relying on which `routeWebSocket` registration wins.
   */
  webSocket?: ((ws: WebSocketRoute) => void) | null;
  /**
   * Overrides the `auth/me` payload. The default fixture user is role
   * `"analyst"`; specs covering the admin-only Configuration tab pass a
   * `{ ...MOCK_USER, role: "admin" }` variant via `test.use({ mockOptions })`
   * rather than a second fixture, following this file's one-surface pattern.
   */
  user?: typeof MOCK_USER;
}

/**
 * Register the full default mock surface on `page`.
 *
 * Must be called before the first navigation. `fixtures.ts` does this for both
 * the `page` and `authenticatedPage` fixtures, so specs get it for free.
 */
export async function installApiMocks(
  page: Page,
  options: MockOptions = {}
): Promise<void> {
  const unmocked: string[] = [];
  unmockedByPage.set(page, unmocked);

  // FIRST, so everything registered below beats it.
  await page.route("**/api/v1/**", async (route) => {
    const url = route.request().url();
    unmocked.push(`${route.request().method()} ${new URL(url).pathname}`);
    await json(
      route,
      { detail: `E2E: no mock registered for ${url}. See e2e/mocks.ts.` },
      501
    );
  });

  /* ── Auth ─────────────────────────────────────────── */
  // The refresh token is an HttpOnly cookie now: the browser holds it, not
  // localStorage, and these mocks answer with the access token alone.
  await page.route("**/api/v1/auth/login", (route) =>
    json(route, { access_token: "mock_access_token", token_type: "bearer" })
  );
  await page.route("**/api/v1/auth/register", (route) =>
    json(route, { access_token: "mock_access_token", token_type: "bearer" })
  );
  await page.route("**/api/v1/auth/me", (route) => json(route, options.user ?? MOCK_USER));
  // Armed by AuthProvider at login. The stub access token is not a JWT, so the
  // timer defaults to ~14 min and this never fires inside a test — mocked
  // anyway, because "never fires" is a property of the fixture data, not a
  // guarantee, and a real call here would be invisible.
  await page.route("**/api/v1/auth/refresh", (route) =>
    json(route, { access_token: "mock_access_token_2", token_type: "bearer" })
  );
  await page.route("**/api/v1/auth/logout", (route) =>
    route.fulfill({ status: 204, body: "" })
  );

  /* ── Dashboard ────────────────────────────────────── */
  await page.route("**/api/v1/dashboard/stats", (route) =>
    json(route, MOCK_DASHBOARD_STATS)
  );
  await page.route("**/api/v1/system/status", (route) =>
    json(route, MOCK_SYSTEM_STATUS)
  );

  /* ── Jobs ─────────────────────────────────────────── */
  await page.route("**/api/v1/jobs?**", (route) =>
    json(route, { items: [MOCK_JOB_SUMMARY], total: 1, page: 1, page_size: 10 })
  );
  // These two do not overlap, so their relative order is irrelevant: a
  // Playwright `*` does not cross a `/`, so `jobs/*` cannot match `jobs/x/events`.
  await page.route("**/api/v1/jobs/*/events**", (route) =>
    json(route, { job_id: MOCK_JOB_DETAIL.id, events: [], count: 0 })
  );
  await page.route("**/api/v1/jobs/*", (route) => {
    const id = new URL(route.request().url()).pathname.split("/").pop() ?? "";
    return json(route, { ...MOCK_JOB_DETAIL, id });
  });

  // The collection path has no query string and no trailing segment, so
  // neither `jobs?**` (literal `?`) nor `jobs/*` matches it. POST /jobs is what
  // the Analyze button on /samples fires.
  await page.route("**/api/v1/jobs", (route) =>
    json(route, { ...MOCK_JOB_DETAIL, id: "job-created", status: "pending" })
  );

  /* ── Reports ──────────────────────────────────────── */
  await page.route("**/api/v1/reports?**", (route) =>
    json(route, {
      items: [MOCK_REPORT_SUMMARY],
      total: 1,
      page: 1,
      page_size: 50,
    })
  );
  // 404 by default: a report does not exist until a run finishes, and the
  // running job above is the default. Specs that assert on a finished report
  // override this.
  await page.route("**/api/v1/reports/job/*", (route) =>
    json(route, { detail: "Report not found" }, 404)
  );
  // Sub-resources. Timeline, STIX and MITRE are fetched on mount by the
  // /process and /detection tabs; signatures and enrich are button-driven.
  await page.route("**/api/v1/reports/*/timeline", (route) =>
    json(route, { rounds: [], confidence_series: [] })
  );
  await page.route("**/api/v1/reports/*/stix", (route) =>
    json(route, { type: "bundle", id: "bundle--mock", objects: [] })
  );
  await page.route("**/api/v1/reports/*/mitre", (route) =>
    json(route, { techniques: [] })
  );
  await page.route("**/api/v1/reports/*/signatures/*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/plain",
      body: "rule Maljan_Mock { condition: false }",
    })
  );
  await page.route("**/api/v1/reports/*/enrich", (route) =>
    json(route, { status: "queued", detail: "Enrichment queued." })
  );

  /* ── Samples ──────────────────────────────────────── */
  await page.route("**/api/v1/samples?**", (route) =>
    json(route, { items: [MOCK_SAMPLE], total: 1, page: 1, page_size: 50 })
  );
  await page.route("**/api/v1/samples/*", (route) => json(route, MOCK_SAMPLE));
  // After `samples/*`, which also matches this path — last registration wins.
  await page.route("**/api/v1/samples/upload", (route) => json(route, MOCK_SAMPLE));
  // A single `*` never crosses a slash, so `samples/*` above cannot match this
  // extra segment — order does not matter here, but it is grouped with the
  // other samples routes for readability. POST uploads a report; GET lists
  // the ones already attached to the sample (empty by default).
  await page.route("**/api/v1/samples/*/sandbox-reports", (route) =>
    route.request().method() === "POST"
      ? json(route, MOCK_SANDBOX_REPORT, 201)
      : json(route, { items: [], total: 0 })
  );
  await page.route("**/api/v1/samples/*/sandbox-reports/*", (route) =>
    route.fulfill({ status: 204, body: "" })
  );

  /* ── Runtime settings (admin) ─────────────────────────
   * Route precedence matters here more than elsewhere: `/settings/schema`,
   * `/settings/export` and `/settings/*` (the per-key DELETE) all have one
   * path segment after `settings`, so the generic `settings/*` handler is
   * registered FIRST and the two literal paths AFTER it, exactly like the
   * jobs section above — last registration wins when patterns overlap.
   * `/settings/test/*` has two segments after `settings` so it never
   * overlaps with `settings/*` and its position doesn't matter.
   * The bare "settings" pattern (no query) and the "settings" + query
   * pattern below are disjoint by construction — a bare-"settings" glob
   * does not match a URL with a "?" per the note atop this file — so
   * GET/PATCH (values, no query) and DELETE-by-group ("?group=") can't
   * collide either. */
  await page.route("**/api/v1/settings/*", (route) => {
    const key = new URL(route.request().url()).pathname.split("/").pop() ?? "";
    return json(route, { reset: [key] });
  });
  await page.route("**/api/v1/settings/schema", (route) =>
    json(route, MOCK_SETTINGS_SCHEMA)
  );
  await page.route("**/api/v1/settings/export", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/plain",
      body: "CORE_NEGOTIATION_RETRY_DELAY=10\n",
    })
  );
  await page.route("**/api/v1/settings/test/*", (route) =>
    json(route, { ok: true, latency_ms: 42, detail: "mock probe ok", models: null })
  );
  await page.route("**/api/v1/settings", (route) =>
    route.request().method() === "PATCH"
      ? json(route, {
          applied: Object.keys(
            (route.request().postDataJSON() as { changes: Record<string, unknown> }).changes
          ),
          applies: { next_job: 1 },
        })
      : json(route, MOCK_SETTINGS_VALUES)
  );
  await page.route("**/api/v1/settings?**", (route) => json(route, { reset: [] }));

  /* ── Audit & API keys ─────────────────────────────── */
  await page.route("**/api/v1/audit/logs?**", (route) =>
    json(route, { items: [MOCK_AUDIT_LOG], total: 1, page: 1, page_size: 20 })
  );
  await page.route("**/api/v1/audit/api-keys?**", (route) =>
    json(route, { items: [MOCK_API_KEY], total: 1, page: 1, page_size: 50 })
  );
  await page.route("**/api/v1/audit/api-keys", (route) =>
    json(route, { ...MOCK_API_KEY, id: "key-2", name: "new key", raw_key: "mlj_secret_value" })
  );
  await page.route("**/api/v1/audit/api-keys/*", (route) =>
    route.fulfill({ status: 204, body: "" })
  );

  /* ── WebSocket ────────────────────────────────────── */
  const wsHandler =
    options.webSocket === undefined
      ? () => {
          /* Connected and silent. Not calling connectToServer() is what keeps
           * this from dialling a real backend. */
        }
      : options.webSocket;
  if (wsHandler) {
    await page.routeWebSocket("**/ws/analysis/**", wsHandler);
  }
}

/**
 * Fail if the page made an API call nobody mocked.
 *
 * Called from the fixture teardown, so it covers every spec without each one
 * remembering to. The point is the name: an uncovered endpoint should say which
 * endpoint it was, not disappear into a 501 the assertion happens to survive.
 */
export function assertNoUnmockedCalls(page: Page): void {
  const unmocked = unmockedByPage.get(page);
  if (!unmocked?.length) return;
  const unique = [...new Set(unmocked)];
  throw new Error(
    `E2E hermeticity: ${unique.length} unmocked API call(s) reached the ` +
      `catch-all and were answered 501:\n  ${unique.join("\n  ")}\n` +
      `Add a handler in e2e/mocks.ts, or page.route(...) in the spec.`
  );
}
