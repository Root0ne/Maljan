/*
 * Wave 10 W10-LINT-DEBT-02 (2026-05-30): this file is Playwright fixture
 * code, not React. ``use(page)`` is the Playwright fixture callback
 * (https://playwright.dev/docs/test-fixtures), not the React 19 ``use``
 * hook. The ``react-hooks/rules-of-hooks`` rule pattern-matches on the
 * identifier and false-positives across the entire E2E suite. Disabling
 * the rule for the file scopes the suppression to where it's actually
 * incorrect.
 */
/* eslint-disable react-hooks/rules-of-hooks */
import { test as base, expect } from "@playwright/test";

/**
 * Playwright fixtures with API mocking for Maljan E2E tests.
 *
 * `authenticatedPage` logs in via mocked API endpoints and returns a page
 * that is already on the dashboard.
 */

export const test = base.extend<{
  authenticatedPage: import("@playwright/test").Page;
}>({
  authenticatedPage: async ({ page }, use) => {
    // Mock login endpoint
    await page.route("**/api/v1/auth/login", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          access_token: "mock_access_token",
          refresh_token: "mock_refresh_token",
        }),
      });
    });

    // Mock current user endpoint
    await page.route("**/api/v1/auth/me", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: "user-1",
          email: "test@example.com",
          full_name: "Test User",
          role: "analyst",
        }),
      });
    });

    // Mock dashboard stats
    await page.route("**/api/v1/dashboard/stats", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
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
        }),
      });
    });

    /* The dashboard awaits stats, jobs and system status together, and a
     * rejection in any of them puts the page into its error state with none of
     * the panels rendered. Only stats was mocked, so every dashboard assertion
     * was really asserting against an error screen — the requests fell through
     * to a real API that rejects the fixture's fake token. `no real backend is
     * required` above is only true if every call the page makes is covered. */
    await page.route("**/api/v1/jobs?**", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          items: [
            {
              id: "job-1",
              sample_id: "sample-1",
              sample_filename: "invoice_scan.exe",
              status: "completed",
              verdict: "Malware",
              overall_confidence: 0.93,
              created_at: "2026-07-26T10:00:00Z",
              completed_at: "2026-07-26T10:12:00Z",
              duration_seconds: 720,
            },
          ],
          total: 1,
          page: 1,
          page_size: 10,
        }),
      });
    });

    await page.route("**/api/v1/system/status", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        /* Matches _SYSTEM_STATUS_SCHEMA in lib/api.ts. The client asserts the
         * shape at runtime and logs drift, so a hand-waved mock turns every
         * dashboard test run into a wall of api-schema-drift warnings. */
        body: JSON.stringify({
          app_name: "Maljan",
          app_version: "0.1.0",
          mock_mode_allowed: false,
          enrichment_enabled: true,
          has_virustotal_key: true,
          has_abuseipdb_key: false,
        }),
      });
    });

    await page.goto("/login");
    await page.fill('input[type="email"]', "test@example.com");
    await page.fill('input[type="password"]', "password123");
    await page.click('button[type="submit"]');

    await page.waitForURL("**/dashboard");
    await use(page);
  },
});

export { expect };
