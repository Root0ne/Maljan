import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright E2E test configuration for the Maljan Next.js frontend.
 *
 * - Starts its own `next dev` before tests (webServer).
 * - Mocks every API call, so no backend is required — and none is contacted.
 * - Runs against Chromium, Firefox, and WebKit.
 *
 * Three settings below are load-bearing. Each one was, at some point, the
 * reason the suite either could not run at all or ran against the wrong thing.
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
 *
 * **A same-origin API.** NEXT_PUBLIC_API_URL/WS_URL point at the Next server's
 * own origin. See the note on `webServer` — this is what makes the suite both
 * hermetic and green on WebKit.
 */
const E2E_PORT = 3100;
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  /* Capped rather than left to Playwright's default, which scales with CPU
   * count. On a 32-core dev box that meant ~42 concurrent browsers, and the
   * constraint here is memory, not cores: the Docker stack and the local LLM
   * leave only a few GB free, and `next dev` compiles each route on first hit,
   * so the whole fleet arrives at an uncompiled page at once. That produced
   * intermittent "element(s) not found" failures — WebKit first, being the
   * heaviest — which look like product bugs and are not. */
  workers: process.env.CI ? 1 : 4,
  /* Above Playwright's 30 s default for the same reason. A spec that passes
   * 6/6 in isolation and fails four of those under a full run is not flaky
   * code, it is a starved machine; raising the ceiling is honest, silently
   * retrying would not be. */
  timeout: 45_000,
  /* Likewise above the 5 s default. Under `next dev` the first test to reach a
   * route waits on its compile, and 5 s is not always enough for that on a
   * loaded machine — the symptom is a single assertion failing in a spec that
   * passes 6/6 on its own. */
  expect: { timeout: 10_000 },
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
      /* WebKit used to bounce to /login on every full page load once the whole
       * suite ran, and the cause was CORS, not anything WebKit-specific about
       * storage: `lib/api.ts` sends Content-Type and Authorization on every
       * request, neither of which is CORS-safelisted, so each cross-origin call
       * was preflighted. Playwright answers those OPTIONS preflights itself for
       * Chromium (CDP) and Firefox (BiDi); its WebKit route does not, so the
       * preflight escaped to the real backend, which rejects an origin it does
       * not know. `getMe()` then rejected with a network error rather than a
       * 401, and both tokens were cleared. Same-origin (see webServer) removes
       * the preflight entirely, so nothing has to synthesise CORS headers. */
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

      /* Point the client at the page's own origin. Two things follow.
       *
       * Hermetic: `lib/api.ts` otherwise defaults to http://127.0.0.1:8000, so
       * on a machine running the dev backend every call the fixtures missed
       * reached the real API and returned real data — tests passed on live
       * responses while appearing to assert on mocks. Now an unmocked call can
       * only reach the Next server, which has no /api routes and no proxy
       * (see next.config.ts), and `e2e/mocks.ts` traps it by name first.
       *
       * Cross-browser: same-origin means no CORS preflight, which is what
       * WebKit was failing on (see the webkit project above).
       *
       * An empty string will not do: api.ts uses `||`, so "" falls through to
       * the 127.0.0.1 default and silently restores both problems.
       */
      NEXT_PUBLIC_API_URL: `http://localhost:${E2E_PORT}`,
      NEXT_PUBLIC_WS_URL: `ws://localhost:${E2E_PORT}`,
    },
  },
});
