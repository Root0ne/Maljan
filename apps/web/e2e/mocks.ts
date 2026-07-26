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

export interface MockOptions {
  /**
   * Handler for `**​/ws/analysis/**`. The default accepts the connection and
   * stays silent, which is enough for pages that merely mount `useWebSocket`.
   * Pass `null` to leave the socket unrouted so the spec can install its own —
   * explicit, rather than relying on which `routeWebSocket` registration wins.
   */
  webSocket?: ((ws: WebSocketRoute) => void) | null;
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
  await page.route("**/api/v1/auth/login", (route) =>
    json(route, {
      access_token: "mock_access_token",
      refresh_token: "mock_refresh_token",
    })
  );
  await page.route("**/api/v1/auth/register", (route) =>
    json(route, {
      access_token: "mock_access_token",
      refresh_token: "mock_refresh_token",
    })
  );
  await page.route("**/api/v1/auth/me", (route) => json(route, MOCK_USER));
  // Armed by AuthProvider at login. The stub refresh token is not a JWT, so the
  // timer defaults to ~14 min and this never fires inside a test — mocked
  // anyway, because "never fires" is a property of the fixture data, not a
  // guarantee, and a real call here would be invisible.
  await page.route("**/api/v1/auth/refresh", (route) =>
    json(route, {
      access_token: "mock_access_token_2",
      refresh_token: "mock_refresh_token_2",
    })
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

  /* ── Reports ──────────────────────────────────────── */
  await page.route("**/api/v1/reports?**", (route) =>
    json(route, { items: [], total: 0, page: 1, page_size: 10 })
  );
  // 404 by default: a report does not exist until a run finishes, and the
  // running job above is the default. Specs that assert on a finished report
  // override this.
  await page.route("**/api/v1/reports/job/*", (route) =>
    json(route, { detail: "Report not found" }, 404)
  );

  /* ── Samples ──────────────────────────────────────── */
  // Not reached by any current spec, but SearchPalette fires samples + jobs +
  // reports on the first keystroke in the header search box.
  await page.route("**/api/v1/samples?**", (route) =>
    json(route, { items: [], total: 0, page: 1, page_size: 10 })
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
