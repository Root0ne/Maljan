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

export const test = base.extend<{
  mockOptions: MockOptions;
  authenticatedPage: import("@playwright/test").Page;
}>({
  mockOptions: [{}, { option: true }],

  page: async ({ page, mockOptions }, use) => {
    await installApiMocks(page, mockOptions);
    await use(page);
    assertNoUnmockedCalls(page);
  },

  authenticatedPage: async ({ page }, use) => {
    /* Seed the session rather than driving the login form.
     *
     * The form version raced Next's hydration: `page.click` sometimes landed
     * before React attached `onSubmit`, the browser performed a *native* form
     * submit, and the test sat on `/login?` until it timed out. Nothing about
     * the ten tests using this fixture is about the login screen — they need a
     * signed-in page, and the login flow itself is covered by `auth.spec.ts`,
     * which drives the real form and handles that race explicitly.
     *
     * `addInitScript` runs before any page script, so `AuthProvider` finds the
     * token on its very first mount and validates it against the mocked
     * `auth/me` — the same code path a real login lands in. */
    await page.addInitScript(() => {
      localStorage.setItem("access_token", "mock_access_token");
      localStorage.setItem("refresh_token", "mock_refresh_token");
    });
    await page.goto("/dashboard");
    await page.waitForURL("**/dashboard");
    await use(page);
  },
});

export { expect };
