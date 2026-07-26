import { test, expect } from "./fixtures";

/**
 * FE-WS-RECONNECT-TEST-01 (audit 2026-05-19), rewritten 2026-07-26.
 *
 * `useWebSocket` reconnects with exponential backoff and full jitter, and
 * deliberately does *not* reconnect on close code 1008 — an auth/policy
 * rejection needs a fresh credential, and retrying just hammers the API with
 * the same bad token. Neither behaviour was covered.
 *
 * The previous version of this spec could not have covered them. It observed
 * `page.on("websocket")` without routing anything, so the browser dialled a
 * real backend; it mocked no API at all, so `AuthProvider` unmounted the page
 * before any retry could fire; and its only assertion —
 * `expect(connectionAttempts).toBeLessThanOrEqual(8)` — **passes when the count
 * is zero**, which is exactly what it was. A green test that cannot fail is
 * worse than no test: it occupies the slot where a real one would go.
 *
 * These drive the socket through `page.routeWebSocket`, so the schedule is
 * exercised against a socket the test controls and no backend is involved.
 *
 * `/process` rather than `/live` on purpose: the live page mounts a *second*
 * `useWebSocket` of its own on top of the analysis layout's, which would make
 * every connection count ambiguous.
 */

const JOB_ID = "00000000-0000-0000-0000-000000000000";

// No default WebSocket route — each test installs its own so it can hold the
// attempt counter in a local, rather than sharing module state across workers.
test.use({ mockOptions: { webSocket: null } });

test.describe("WebSocket reconnect", () => {
  test("retries after the server drops the connection", async ({
    authenticatedPage,
  }) => {
    let attempts = 0;
    await authenticatedPage.routeWebSocket("**/ws/analysis/**", (ws) => {
      attempts += 1;
      // Drop the first two, then accept: the count settles instead of climbing,
      // so the assertions below are about the schedule, not about how long the
      // test happened to wait.
      if (attempts <= 2) ws.close({ code: 1011, reason: "e2e: forced drop" });
    });

    await authenticatedPage.goto(`/analysis/${JOB_ID}/process`);

    // Two drops must produce two retries. Generous timeout: the delay is
    // jittered, and on a successful open the schedule resets to its 1 s base.
    await expect
      .poll(() => attempts, { timeout: 15_000 })
      .toBeGreaterThanOrEqual(3);

    // And then it must stop. This is the half the old fixed-3s-timer
    // regression would have broken: a client that keeps redialling an
    // already-open socket is the outage amplifier the backoff exists to avoid.
    const settled = attempts;
    await authenticatedPage.waitForTimeout(3_000);
    expect(attempts).toBe(settled);
  });

  test("does not retry after a policy close (1008)", async ({
    authenticatedPage,
  }) => {
    let attempts = 0;
    await authenticatedPage.routeWebSocket("**/ws/analysis/**", (ws) => {
      attempts += 1;
      ws.close({ code: 1008, reason: "e2e: invalid credentials" });
    });

    await authenticatedPage.goto(`/analysis/${JOB_ID}/process`);

    await expect.poll(() => attempts, { timeout: 10_000 }).toBe(1);

    // Longer than the 1 s base delay by a wide margin, so a regression that
    // dropped the 1008 check would have reconnected several times by now.
    await authenticatedPage.waitForTimeout(3_000);
    expect(attempts).toBe(1);
  });
});
