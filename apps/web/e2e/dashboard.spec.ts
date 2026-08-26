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

  test("recent analyses identify samples by name, not an opaque UUID", async ({
    authenticatedPage,
  }) => {
    await expect(
      authenticatedPage.getByRole("heading", { name: /recent analyses/i })
    ).toBeVisible();

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
});
