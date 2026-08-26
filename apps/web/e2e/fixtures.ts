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
import { assertNoUnmockedCalls, installApiMocks, type MockOptions } from "./mocks";

/**
 * Playwright fixtures for the Maljan E2E suite.
 *
 * Both fixtures install the full mock surface from `mocks.ts` and both assert,
 * on teardown, that nothing escaped it. Every spec must import `test` from
 * here rather than from `@playwright/test` — a spec that imports the raw one
 * gets no mocks, and (before the API was made same-origin) silently tested the
 * developer's own backend. `auth.spec.ts` and `ws_reconnect.spec.ts` both did.
 *
 * - `page` — mocked, not logged in. For specs about the unauthenticated state.
 * - `authenticatedPage` — mocked and already on the dashboard.
 *
 * `mockOptions` is an overridable option fixture; a spec that needs different
 * mock wiring (e.g. its own WebSocket handler) sets it with
 * `test.use({ mockOptions: { … } })` instead of racing the fixture's own
 * registrations.
 */

/**
 * Put a valid session in localStorage before any page script runs.
 *
 * `addInitScript` is what makes this equivalent to a real login rather than a
 * shortcut around it: AuthProvider finds the token on its very first mount and
 * validates it against the mocked `auth/me`, which is the same code path the
 * login form lands in.
 */
async function seedSession(page: import("@playwright/test").Page) {
  await page.addInitScript(() => {
    localStorage.setItem("access_token", "mock_access_token");
    localStorage.setItem("refresh_token", "mock_refresh_token");
  });
}

export const test = base.extend<{
  mockOptions: MockOptions;
  sessionPage: import("@playwright/test").Page;
  authenticatedPage: import("@playwright/test").Page;
}>({
  mockOptions: [{}, { option: true }],

  page: async ({ page, mockOptions }, use) => {
    await installApiMocks(page, mockOptions);
    await use(page);
    assertNoUnmockedCalls(page);
  },

  /**
   * A mocked page with a session but no navigation yet.
   *
   * `authenticatedPage` lands on /dashboard, which is convenient but not free:
   * the dashboard fires three requests on mount, and navigating away mid-flight
   * aborts them. WebKit reports each abort as a page-level error ("…due to
   * access control checks"), so a spec that watches for uncaught exceptions
   * sees four phantom failures that have nothing to do with what it is testing.
   * Specs that go straight somewhere else should start here.
   */
  sessionPage: async ({ page }, use) => {
    await seedSession(page);
    await use(page);
  },

  authenticatedPage: async ({ page }, use) => {
    /* Seed the session rather than driving the login form.
     *
     * The form version raced Next's hydration: `page.click` sometimes landed
     * before React attached `onSubmit`, the browser performed a *native* form
     * submit, and the test sat on `/login?` until it timed out. Nothing about
     * the specs using this fixture is about the login screen — they need a
     * signed-in page, and the login flow itself is covered by `auth.spec.ts`,
     * which drives the real form and handles that race explicitly. */
    await seedSession(page);
    await page.goto("/dashboard");
    await page.waitForURL("**/dashboard");
    await use(page);
  },
});

/**
 * Every error banner on the page, and nothing else.
 *
 * `getByRole("alert")` cannot be used directly: Next renders a permanent
 * `#__next-route-announcer__` with `role="alert"` on every page, so the plain
 * query is never empty and `toHaveCount(0)` never passes. Excluding it gives
 * the assertion the pages' own error branches were given `role="alert"` for —
 * a blanket "nothing on this page quietly failed".
 */
export function alerts(page: import("@playwright/test").Page) {
  return page.locator('[role="alert"]:not(#__next-route-announcer__)');
}

export { expect };
