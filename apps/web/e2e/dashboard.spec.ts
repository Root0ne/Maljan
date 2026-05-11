import { test, expect } from "./fixtures";

test.describe("Dashboard", () => {
  test("dashboard shows stats cards", async ({ authenticatedPage }) => {
    await expect(
      authenticatedPage.locator("text=Total Jobs")
    ).toBeVisible();
    await expect(
      authenticatedPage.locator("text=Total Samples")
    ).toBeVisible();
  });

  test("dashboard shows verdict distribution", async ({ authenticatedPage }) => {
    await expect(
      authenticatedPage.locator("text=Malware")
    ).toBeVisible();
    await expect(
      authenticatedPage.locator("text=Benign")
    ).toBeVisible();
  });
});
