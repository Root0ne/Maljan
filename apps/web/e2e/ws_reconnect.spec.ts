import { test, expect } from "./fixtures";

/**
 * FE-WS-RECONNECT-TEST-01 (audit 2026-05-19), rewritten 2026-07-26.
 *
 * The run store reconnects with exponential backoff and full jitter, and
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
 * The schedule moved into the run store, which owns the one socket a job
 * gets; the page under test is simply a page that reads a run.
 */

const JOB_ID = "00000000-0000-0000-0000-000000000000";

// No default WebSocket route — each test installs its own so it can hold the
// attempt counter in a local, rather than sharing module state across workers.
test.use({ mockOptions: { webSocket: null } });

test.describe("WebSocket reconnect", () => {
  test("retries after the server drops the connection", async ({
    authenticatedPage,
  }) => {
    // Two jittered backoff windows plus a settling period; this one genuinely
    // spends ~20 s waiting rather than doing work, so give it the headroom
    // instead of trimming the waits until the assertions stop meaning anything.
    test.slow();
    let attempts = 0;
    await authenticatedPage.routeWebSocket("**/ws/analysis/**", (ws) => {
      attempts += 1;
      // Drop the first two, then accept: the count settles instead of climbing,
      // so the assertions below are about the schedule, not about how long the
      // test happened to wait.
      if (attempts <= 2) ws.close({ code: 1011, reason: "e2e: forced drop" });
    });

    await authenticatedPage.goto(`/analysis/${JOB_ID}/evidence/conversation`);

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

    await authenticatedPage.goto(`/analysis/${JOB_ID}/evidence/conversation`);

    await expect.poll(() => attempts, { timeout: 10_000 }).toBe(1);

    // Longer than the 1 s base delay by a wide margin, so a regression that
    // dropped the 1008 check would have reconnected several times by now.
    await authenticatedPage.waitForTimeout(3_000);
    expect(attempts).toBe(1);
  });

  test("renews once after a rejected-credential close (4401), redials once, then stops", async ({
    authenticatedPage,
  }) => {
    // 4401 is the server's dedicated "credential rejected" code
    // (apps/api/app/api/ws.py). The run store no longer gives up on it at
    // once: an access token that expired mid-run is replaced through the
    // refresh cookie and the feed redialled with the new one. The mocked
    // refresh answers with a new token (e2e/mocks.ts), so there is exactly one
    // redial; this server refuses that one too, and a second credential
    // refusal before any socket has established is final — one renewal per
    // refusal chain, so a server that refuses every token cannot become a
    // refresh-and-redial loop.
    let attempts = 0;
    let refreshes = 0;
    await authenticatedPage.route("**/api/v1/auth/refresh", (route) => {
      refreshes += 1;
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ access_token: "mock_access_token_2", token_type: "bearer" }),
      });
    });
    await authenticatedPage.routeWebSocket("**/ws/analysis/**", (ws) => {
      attempts += 1;
      ws.close({ code: 4401, reason: "e2e: credential rejected" });
    });

    await authenticatedPage.goto(`/analysis/${JOB_ID}/evidence/conversation`);

    // The first dial, the renewal, and the one redial with the new token.
    await expect.poll(() => attempts, { timeout: 10_000 }).toBe(2);
    expect(refreshes).toBe(1);

    // Well past the backoff (its first windows are 1 s and 2 s): a regression
    // that renewed on every refusal would have redialled again by now.
    await authenticatedPage.waitForTimeout(5_000);
    expect(attempts).toBe(2);
    expect(refreshes).toBe(1);
  });
});
