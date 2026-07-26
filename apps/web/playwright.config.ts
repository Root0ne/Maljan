import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright E2E test configuration for the Maljan Next.js frontend.
 *
 * - Starts its own `next dev` before tests (webServer).
 * - Mocks API responses so no real backend is required for E2E tests.
 * - Runs against Chromium, Firefox, and WebKit.
 *
 * Two settings below are load-bearing and were the reason the whole suite
 * failed locally (2026-07-26):
 *
 * **Its own port.** `baseURL` used to be :3000, the same port a dev server or
 * the docker `frontend` container listens on, and `reuseExistingServer` then
 * quietly ran the tests against whatever was already there — a production
 * image built with different env, not the tree under test.
 *
 * **Auth forced on.** `apps/web/.env.local` sets NEXT_PUBLIC_AUTH_DISABLED=true
 * so local development skips the login screen. That bypass also removes the
 * login form the `authenticatedPage` fixture drives, so every test that used
 * the fixture died on a detached submit button. `process.env` outranks
 * `.env.local` in Next's load order, so setting it here pins the suite to the
 * authenticated flow it is actually written to exercise, whatever the machine's
 * dev setup happens to be.
 */
const E2E_PORT = 3100;
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: "html",
  use: {
    baseURL: `http://localhost:${E2E_PORT}`,
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      /* UNRESOLVED locally (2026-07-26). Chromium and Firefox are 13/13; WebKit
       * passes auth.spec in isolation and then bounces to /login on any full
       * page load once the whole suite runs — including a plain
       * goto("/dashboard"), so it is not specific to any one spec. It is
       * entangled with the non-hermetic mocking noted on webServer below (a dev
       * backend on :8000 answers whatever the fixtures miss), and was not root
       * caused. Left enabled rather than quietly dropped: a browser silently
       * removed from the matrix is a gap nobody sees again. */
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
  ],
  webServer: {
    command: `npm run dev -- --port ${E2E_PORT}`,
    url: `http://localhost:${E2E_PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      // Outranks .env.local (Next load order: process.env first), so the login
      // flow exists even on a machine configured to bypass it.
      NEXT_PUBLIC_AUTH_DISABLED: "false",
    },
    // KNOWN GAP (2026-07-26): the suite is not hermetic. lib/api.ts falls back
    // to 127.0.0.1:8000, so on a machine running the dev backend any call the
    // fixtures do not mock reaches the real API and returns real data — the
    // header comment's "no real backend is required" is aspirational. Pointing
    // NEXT_PUBLIC_API_URL at a dead port here proves it: 20 of 39 tests fail,
    // because they are relying on live responses rather than mocks. Closing
    // that means completing the fixture mocks, which is worth doing but is not
    // a config change.
  },
});
