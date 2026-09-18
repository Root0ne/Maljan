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

test.describe("Analyses", () => {
  test("lists runs by sample name, with the verdict of the ones that finished", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/jobs");

    // "Analyses — 1 result"; only rendered on success.
    await expect(page.getByRole("heading", { name: /^Analyses/ })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Filters" })).toBeVisible();
    await expect(page.getByRole("link", { name: /invoice_scan\.exe/ })).toBeVisible();
    // The verdict the Reports page used to carry, on the row it belongs to.
    // The backend's raw "Malware" is owed to the reader as "Malicious".
    await expect(page.getByText("Malicious").first()).toBeVisible();
    await expect(page.getByText("Malware", { exact: true })).toHaveCount(0);
    await expectNoAlerts(page);
  });

  /* A report is a completed job, so the reports table was this table with one
   * filter already applied. The old route lands on exactly that. */
  test("/reports redirects into the list with its status filter applied", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/reports");

    await expect(page).toHaveURL(/\/jobs\?status=completed$/, { timeout: 20_000 });
    await expect(page.getByRole("link", { name: /invoice_scan\.exe/ })).toBeVisible();
    await expectNoAlerts(page);
  });

  test("a status nothing matches empties the list and says which one", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/jobs");
    await page.getByRole("button", { name: /^failed/ }).click();
    await expect(page.getByText("No failed analysis.")).toBeVisible();

    await page.getByRole("button", { name: /^completed/ }).click();
    await expect(page.getByRole("link", { name: /invoice_scan\.exe/ })).toBeVisible();
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

test.describe("Settings", () => {
  /* The <h1> and both <h2>s render unconditionally here, so they prove nothing.
   * The form is the success branch. */
  test("shows the profile form populated from the session", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await expect(page).toHaveURL(/\/settings\/profile$/);

    await expect(page.getByLabel("Full Name")).toHaveValue("Test User");
    await expect(page.getByLabel("Email")).toHaveValue("test@example.com");
    await expect(page.getByRole("button", { name: "Save changes" })).toBeVisible();
    await expectNoAlerts(page);
  });

  test("the API keys tab lists existing keys", async ({ authenticatedPage: page }) => {
    await page.goto("/settings/api-keys");

    await expect(page.getByText("CI/CD integration")).toBeVisible();
    await expect(page.getByText(/mlj_a1b2/)).toBeVisible();
    await expect(page.getByText("Active")).toBeVisible();
    // The empty state used to render directly under the error banner, so an
    // assertion on "no keys" passed on a failed request. Neither may appear.
    await expect(page.getByText("No API keys found.")).toHaveCount(0);
    await expectNoAlerts(page);
  });

  /* The copy button was the one control on this page with no coverage: the
   * clipboard is unavailable in the test browser's context, so the button
   * would otherwise only ever take its "Select and copy the key" branch. */
  test("copying a freshly created key reports Copied", async ({ authenticatedPage: page }) => {
    const copied: string[] = [];
    await page.exposeFunction("recordCopy", (text: string) => {
      copied.push(text);
    });
    await page.addInitScript(() => {
      Object.defineProperty(navigator, "clipboard", {
        configurable: true,
        value: {
          writeText: (text: string) =>
            (window as unknown as { recordCopy: (t: string) => void }).recordCopy(text),
        },
      });
    });

    await page.goto("/settings/api-keys");
    await page.getByLabel("Key name").fill("copy test");
    await page.getByRole("button", { name: "Create", exact: true }).click();

    const copy = page.getByRole("button", { name: "Copy", exact: true });
    await expect(copy).toBeVisible();
    await copy.click();

    await expect(page.getByRole("button", { name: "Copied" })).toBeVisible();
    await expect(page.getByText("Select and copy the key")).toHaveCount(0);
    expect(copied).toEqual(["mlj_secret_value"]);
  });
});

/* A4 (dev audit 2026-09-06): every one of these headers hard-coded its plural,
 * so a list holding exactly one row announced "1 RESULTS", "1 files" and
 * "1 total entries". Each mocked list holds one row, which is the case that
 * used to read wrong. */
test.describe("Result counts", () => {
  test("a single row is counted in the singular on every list", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/jobs");
    await expect(page.getByRole("heading", { name: "Analyses — 1 result" })).toBeVisible();

    await page.goto("/samples");
    await expect(page.getByRole("heading", { name: "Samples — 1 file" })).toBeVisible();

    await page.goto("/audit");
    await expect(page.getByText("1 total entry")).toBeVisible();
  });
});

/* A5 (dev audit 2026-09-06): an unknown URL rendered Next's own 404 with no
 * chrome and no way back into the app. */
test.describe("404", () => {
  test("an unknown route offers a way back into the app", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/nonexistent-route");

    await expect(page.getByRole("heading", { name: "Page not found" })).toBeVisible();
    await page.getByRole("link", { name: "Back to dashboard" }).click();
    await expect(page).toHaveURL(/\/dashboard/);
  });
});

test.describe("Audit log", () => {
  /* Reached by URL: the sidebar link is admin-only and the mocked session is an
   * analyst. The page itself does not gate — that is the backend's job — so
   * this is testing the page, not the authorisation. */
  test("lists audit entries", async ({ authenticatedPage: page }) => {
    await page.goto("/audit");

    await expect(page.getByRole("heading", { name: "Audit Logs" })).toBeVisible();
    // The action reads as a sentence, the actor is drawn at all, and the IP
    // column survives because this fixture row has one.
    await expect(page.getByText("Job create")).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "Who" })).toBeVisible();
    await expect(page.getByText("10.0.0.5")).toBeVisible();
    await expect(page.getByText("1 total entry")).toBeVisible();
    await expectNoAlerts(page);
  });

  /* C-I17: the log had no way to narrow 1766 entries but Previous and Next. */
  test("narrows the log by action, through the endpoint", async ({
    authenticatedPage: page,
  }) => {
    const asked: string[] = [];
    await page.route("**/api/v1/audit/logs?**", (route) => {
      asked.push(new URL(route.request().url()).searchParams.get("action") ?? "");
      return route.fulfill({
        json: { items: [], total: 0, page: 1, page_size: 20, pages: 0 },
      });
    });
    await page.goto("/audit");

    await page.getByLabel("Action").fill("settings");
    await page.getByRole("button", { name: "Filter" }).click();

    await expect(page.getByText("No entry matches “settings”.")).toBeVisible();
    expect(asked).toContain("settings");
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
