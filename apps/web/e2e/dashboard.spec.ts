import { test, expect } from "./fixtures";

// Audit 2026-07-26: these assertions had drifted from the UI and were failing.
// The cards read "TOTAL ANALYSES / COMPLETED / FAILED / AVG DURATION" — there is
// no "Total Jobs" and no "Total Samples" card at all. The verdict legend renders
// the normalised label "Malicious", never the backend's raw "Malware", and
// "Benign" only appears when such a report exists, so asserting it
// unconditionally made the test depend on seed data.
test.describe("Dashboard", () => {
  test("dashboard shows stats cards", async ({ authenticatedPage }) => {
    for (const label of ["TOTAL ANALYSES", "COMPLETED", "FAILED", "AVG DURATION"]) {
      await expect(
        authenticatedPage.getByText(label, { exact: false }).first()
      ).toBeVisible();
    }
  });

  test("dashboard shows the verdict distribution panel", async ({ authenticatedPage }) => {
    await expect(
      authenticatedPage.getByRole("heading", { name: /verdict distribution/i })
    ).toBeVisible();

    // Either a normalised verdict label or the documented empty state — never
    // the raw backend value "Malware".
    await expect(
      authenticatedPage
        .getByText(/Malicious|Suspicious|Benign|No verdict data available/i)
        .first()
    ).toBeVisible();
  });

  test("the latest runs identify samples by name, not an opaque UUID", async ({
    authenticatedPage,
  }) => {
    await expect(
      authenticatedPage.getByRole("heading", { name: /latest runs/i })
    ).toBeVisible();
    // A way into the one list, not a second copy of it.
    await expect(
      authenticatedPage.getByRole("link", { name: "Every analysis" })
    ).toHaveAttribute("href", "/jobs");

    // The jobs list is mocked (e2e/mocks.ts, MOCK_JOB_SUMMARY), so this no
    // longer needs the "if there are no rows, skip" escape hatch it carried
    // while it was reading whatever the dev database happened to hold — an
    // escape hatch that made the test silently vacuous on an empty database.
    const rows = authenticatedPage.locator('a[href^="/analysis/"]');
    await expect(rows).toHaveCount(1);

    // Regression guard for the audit finding where every row rendered the same
    // sample_id UUID prefix, making the list unreadable.
    const firstRowText = (await rows.first().innerText()).trim();
    expect(firstRowText).not.toMatch(/^[0-9a-f]{8}-[0-9a-f]{3}\b/i);
    expect(firstRowText).toContain("invoice_scan.exe");
  });

  test("a finished run carries its verdict as a chip, in words", async ({
    authenticatedPage,
  }) => {
    const row = authenticatedPage.locator('a[href^="/analysis/"]').first();
    const chip = row.locator("[data-verdict-chip]");
    // The backend's "Malware" is owed to the reader as "Malicious", and the
    // colour is the second carrier of it, not the only one.
    await expect(chip).toHaveText("Malicious");
    await expect(chip).toHaveClass(/text-status-red/);
    await expect(row.getByText("completed", { exact: true })).toHaveCount(0);
  });

  test("a run with no verdict is drawn by its status, never by an empty chip", async ({
    sessionPage: page,
  }) => {
    await page.route("**/api/v1/reports?**", (route) =>
      route.fulfill({ json: { items: [], total: 0, page: 1, page_size: 20 } })
    );
    await page.goto("/dashboard");
    const row = page.locator('a[href^="/analysis/"]').first();
    await expect(row).toContainText("invoice_scan.exe");
    await expect(row.locator("[data-verdict-chip]")).toHaveCount(0);
    await expect(row.getByText("completed", { exact: true })).toBeVisible();
  });

  test("the tools recent runs used are flat bars with their counts printed", async ({
    authenticatedPage,
  }) => {
    const section = authenticatedPage.getByRole("region", { name: "Tools used" });
    await expect(section).toBeVisible();
    await expect(section.getByText("Calls over the last 3 completed runs")).toBeVisible();

    const items = section.getByRole("listitem");
    await expect(items).toHaveCount(3);
    // Most calls first, the count printed beside the bar.
    await expect(items.first()).toContainText("pe_info");
    await expect(items.first()).toContainText("9");

    // A long name is cut on screen and whole on hover and to a screen reader.
    const long = "strings_extract_with_a_name_long_enough_to_truncate";
    await expect(section.locator(`[title="${long}"]`)).toHaveCount(1);
    await expect(items.nth(1).locator(".sr-only")).toHaveText(
      `${long}: 4 calls in 2 of 3 runs`
    );
  });

  test("no tools section when no recent run called anything", async ({ sessionPage: page }) => {
    await page.route("**/api/v1/dashboard/tools**", (route) =>
      route.fulfill({ json: { limit: 20, runs: 0, tools: [] } })
    );
    await page.goto("/dashboard");
    await expect(page.getByRole("heading", { name: /latest runs/i })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Tools used" })).toHaveCount(0);
  });
});
