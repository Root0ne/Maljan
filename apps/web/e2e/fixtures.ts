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

    await page.goto("/login");
    await page.fill('input[type="email"]', "test@example.com");
    await page.fill('input[type="password"]', "password123");
    await page.click('button[type="submit"]');

    await page.waitForURL("**/dashboard");
    await use(page);
  },
});

export { expect };
