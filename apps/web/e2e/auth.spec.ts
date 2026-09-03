import { test, expect } from "./fixtures";

/*
 * These import `test` from ./fixtures, not from @playwright/test. Importing the
 * raw one — as this file used to — means no mocks at all: the third test loads
 * the whole `(app)` tree, which fires dashboard stats, jobs and system status
 * before the redirect lands, and every one of them went to a real backend. The
 * fixture also fails the test if any call escapes the mocks, which the raw
 * `test` cannot do.
 *
 * `page` here is the unauthenticated fixture: mocked, but with no token in
 * localStorage and no login performed.
 */

test.describe("Authentication", () => {
  test("login page loads with form elements", async ({ page }) => {
    await page.goto("/login");
    await expect(page.locator('input[type="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test("successful login redirects to dashboard", async ({ page }) => {
    /* Retried as a unit because of a hydration race: until React attaches
     * `onSubmit`, clicking the button performs a *native* form submit, which
     * reloads `/login?` and drops the typed credentials. Re-filling inside the
     * retry means the second attempt runs against a page that has had time to
     * hydrate. Waiting on a React-internals marker instead would be more
     * precise and far more brittle. */
    await expect(async () => {
      await page.goto("/login");
      await page.fill('input[type="email"]', "test@example.com");
      await page.fill('input[type="password"]', "password123");
      await page.click('button[type="submit"]');
      await page.waitForURL("**/dashboard", { timeout: 5_000 });
    }).toPass({ timeout: 30_000 });

    /* `waitForURL` alone is satisfied by login/page.tsx's router.push and says
     * nothing about whether the session survived. AuthProvider re-validates on
     * mount and bounces back to /login if getMe fails, so assert on something
     * only a live session renders — otherwise this passes on a page that is
     * about to throw the user out, which is exactly how the WebKit failure
     * stayed hidden. */
    await expect(page.getByText("TOTAL ANALYSES").first()).toBeVisible();
    await expect(page).toHaveURL(/\/dashboard/);
  });

  /* The two halves of one rule: a session the server *rejected* is over, a
   * session the server never answered about is not. AuthProvider used to
   * `catch {}` both and delete the tokens either way, so a backend restart
   * signed everyone out and destroyed their refresh token — indistinguishable,
   * from the user's side, from a normal expiry, which is why it never got
   * reported. It is also what turned a failed CORS preflight into WebKit's
   * unexplained bounce to /login in this very suite. */
  test("a server outage shows an error and keeps the session", async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem("access_token", "mock_access_token");
    });
    await page.route("**/api/v1/auth/me", (route) => route.abort("connectionrefused"));

    await page.goto("/dashboard");

    // By heading, not by role=alert: Next renders its own always-present
    // route announcer with role="alert", so that selector is ambiguous.
    await expect(
      page.getByRole("heading", { name: /could not reach the server/i })
    ).toBeVisible({ timeout: 20_000 });
    await expect(page.getByRole("button", { name: /try again/i })).toBeVisible();
    await expect(page).toHaveURL(/\/dashboard/);
    expect(await page.evaluate(() => localStorage.getItem("access_token"))).toBe(
      "mock_access_token"
    );
  });

  test("a rejected session does sign the user out", async ({ page }) => {
    await page.addInitScript(() => {
      localStorage.setItem("access_token", "expired_token");
    });
    await page.route("**/api/v1/auth/me", (route) =>
      route.fulfill({
        status: 401,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Token expired" }),
      })
    );

    await page.goto("/dashboard");

    await expect(page).toHaveURL(/\/login/, { timeout: 20_000 });
    expect(await page.evaluate(() => localStorage.getItem("access_token"))).toBeNull();
  });

  test("the register page renders its form", async ({ page }) => {
    // The only other route in the (auth) group, and the only one that can
    // create an account. It had no coverage at all.
    await page.goto("/register");
    await expect(page.locator('input[type="email"]')).toBeVisible();
    await expect(page.locator('input[type="password"]').first()).toBeVisible();
    await expect(page.getByRole("button", { name: /sign up|register|create/i })).toBeVisible();
  });

  test("unauthenticated user is redirected to login", async ({ page }) => {
    await page.goto("/dashboard");
    /* The guard is a client-side effect in AuthProvider, so it cannot fire
     * until the route has compiled and hydrated. Under `next dev` the first
     * test to reach /dashboard pays that compile, which on WebKit overran the
     * 5 s default. The assertion is that it redirects, not how quickly. */
    await expect(page).toHaveURL(/\/login/, { timeout: 20_000 });
  });

  /* Task 11: the refresh token lives in an HttpOnly cookie now, not in
   * localStorage — the browser can no longer read it, let alone hold it. */
  test("login keeps only the access token in storage and sends credentials", async ({
    page,
  }) => {
    // Same hydration race as "successful login redirects to dashboard" above
    // — retry the whole fill+click+request as one unit rather than repeating
    // the explanation.
    let req: import("@playwright/test").Request;
    await expect(async () => {
      await page.goto("/login");
      const [request] = await Promise.all([
        page.waitForRequest(
          (r) => r.url().endsWith("/api/v1/auth/login") && r.method() === "POST",
          { timeout: 5_000 }
        ),
        (async () => {
          await page.getByLabel(/email/i).fill("a@b.c");
          await page.getByLabel(/password/i).fill("pw");
          await page.getByRole("button", { name: /sign in/i }).click();
        })(),
      ]);
      req = request;
    }).toPass({ timeout: 30_000 });
    // The browser decides whether to attach the cookie header; what matters
    // here is that the request was made at all — `credentials: "include"` is
    // reviewed directly in api.ts.
    expect(req!.url()).toContain("/api/v1/auth/login");
    await page.waitForURL(/dashboard/);
    const stored = await page.evaluate(() => Object.keys(localStorage));
    expect(stored).toContain("access_token");
    expect(stored).not.toContain("refresh_token");
  });

  test("sign out calls logout and clears the access token", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/dashboard");
    const logout = page.waitForRequest((r) =>
      r.url().endsWith("/api/v1/auth/logout")
    );
    await page.getByRole("button", { name: /sign out/i }).click();
    await logout;
    await page.waitForURL(/login/);
    expect(
      await page.evaluate(() => localStorage.getItem("access_token"))
    ).toBeNull();
  });
});
