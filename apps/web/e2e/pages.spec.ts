import { alerts, test, expect } from "./fixtures";

/**
 * The five list/admin pages, none of which had ever been loaded by a test.
 *
 * Each asserts three things, and the combination is the point:
 *
 *  1. A landmark that renders **only** in the success branch. Several of these
 *     pages return early on error with a bare div and no heading, so the
 *     heading's presence is itself the proof the fetch succeeded — but not on
 *     `/settings` and `/audit`, whose `<h1>` renders in every state. For those,
 *     assert on data instead.
 *  2. A piece of the mocked payload, so the page is proven to have rendered the
 *     response rather than an empty table.
 *  3. `role="alert"` count zero. Every error branch on these pages now carries
 *     that role, so this is a blanket "nothing quietly failed" check — and it
 *     is what stops these tests from going vacuous the way the old dashboard
 *     ones did, where the assertions passed against an error screen.
 */

/** No error banner anywhere on the page. */
async function expectNoAlerts(page: import("@playwright/test").Page) {
  await expect(alerts(page)).toHaveCount(0);
}

test.describe("Jobs", () => {
  test("lists jobs by sample name", async ({ authenticatedPage: page }) => {
    await page.goto("/jobs");

    // "Analysis Jobs — 1 results"; only rendered on success.
    await expect(page.getByRole("heading", { name: /^Analysis Jobs/ })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Filters" })).toBeVisible();
    await expect(page.getByRole("link", { name: /invoice_scan\.exe/ })).toBeVisible();
    await expectNoAlerts(page);
  });
});

test.describe("Samples", () => {
  test("lists samples with their hash and size", async ({ authenticatedPage: page }) => {
    await page.goto("/samples");

    await expect(page.getByRole("heading", { name: /^Samples/ })).toBeVisible();
    // The table and its column headers are not rendered at all when the list is
    // empty, so this doubles as proof the row exists.
    await expect(page.getByRole("columnheader", { name: "Filename" })).toBeVisible();
    await expect(page.getByText("invoice_scan.exe")).toBeVisible();
    await expectNoAlerts(page);
  });

  test("the detail modal shows the full hashes", async ({ authenticatedPage: page }) => {
    await page.goto("/samples");
    await page.getByRole("button", { name: "Details" }).first().click();

    const modal = page.getByRole("dialog");
    await expect(modal).toBeVisible();
    await expect(modal.getByText("Sample Details")).toBeVisible();
    await expect(modal.getByText(/9f86d081884c7d659a2feaa0c55ad015/)).toBeVisible();
  });
});

test.describe("Reports", () => {
  test("lists reports and normalises the verdict", async ({ authenticatedPage: page }) => {
    await page.goto("/reports");

    await expect(page.getByRole("heading", { name: "Reports", exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: /invoice_scan\.exe/ })).toBeVisible();
    // The mock verdict is the backend's raw "Malware"; the UI owes the reader
    // "Malicious". Same rule the dashboard and transcript specs enforce.
    await expect(page.getByText("Malicious").first()).toBeVisible();
    await expect(page.getByText("Malware", { exact: true })).toHaveCount(0);
    await expectNoAlerts(page);
  });

  test("the verdict tabs filter client-side", async ({ authenticatedPage: page }) => {
    await page.goto("/reports");
    await page.getByRole("button", { name: /^Benign/ }).click();
    await expect(page.getByText("No reports found.")).toBeVisible();

    await page.getByRole("button", { name: /^Malicious/ }).click();
    await expect(page.getByRole("link", { name: /invoice_scan\.exe/ })).toBeVisible();
  });
});

test.describe("Settings", () => {
  /* The <h1> and both <h2>s render unconditionally here, so they prove nothing.
   * The form is the success branch. */
  test("shows the profile form populated from the session", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");

    await expect(page.getByLabel("Full Name")).toHaveValue("Test User");
    await expect(page.getByLabel("Email")).toHaveValue("test@example.com");
    await expect(page.getByRole("button", { name: "Save changes" })).toBeVisible();
    await expectNoAlerts(page);
  });

  test("the API keys tab lists existing keys", async ({ authenticatedPage: page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "API Keys" }).click();

    await expect(page.getByText("CI/CD integration")).toBeVisible();
    await expect(page.getByText(/mlj_a1b2/)).toBeVisible();
    await expect(page.getByText("Active")).toBeVisible();
    // The empty state used to render directly under the error banner, so an
    // assertion on "no keys" passed on a failed request. Neither may appear.
    await expect(page.getByText("No API keys found.")).toHaveCount(0);
    await expectNoAlerts(page);
  });
});

test.describe("Audit log", () => {
  /* Reached by URL: the sidebar link is admin-only and the mocked session is an
   * analyst. The page itself does not gate — that is the backend's job — so
   * this is testing the page, not the authorisation. */
  test("lists audit entries", async ({ authenticatedPage: page }) => {
    await page.goto("/audit");

    await expect(page.getByRole("heading", { name: "Audit Logs" })).toBeVisible();
    await expect(page.getByText("job.create")).toBeVisible();
    await expect(page.getByText("10.0.0.5")).toBeVisible();
    await expect(page.getByText(/1 total entries/)).toBeVisible();
    await expectNoAlerts(page);
  });

  test("a failed fetch is reported, not disguised as an empty log", async ({
    authenticatedPage: page,
  }) => {
    /* The regression this guards: the error banner and "No audit logs found."
     * used to render together, so a broken page and an empty one were
     * indistinguishable — and the empty-state assertion passed on both. */
    await page.route("**/api/v1/audit/logs?**", (route) =>
      route.fulfill({
        status: 500,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Database unavailable" }),
      })
    );
    await page.goto("/audit");

    await expect(alerts(page)).toContainText(/database unavailable/i);
    await expect(page.getByText("No audit logs found.")).toHaveCount(0);
  });
});
