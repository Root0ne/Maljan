import { test, expect } from "./fixtures";

/**
 * The global search palette.
 *
 * It lives in the app header, so it is mounted on every authenticated page and
 * fires three requests — samples, jobs, reports — on the first keystroke. Those
 * three mocks existed in the fixture surface with nothing exercising them,
 * which meant the palette's whole network path was untested while looking
 * covered.
 */

const SEARCH_LABEL = /Search files, hashes, IPs, or malware families/;

/**
 * Press Ctrl+K until the palette opens.
 *
 * The shortcut is registered by a `useEffect`, so a keypress that lands before
 * React hydrates goes nowhere — the same race that used to make the login
 * fixture submit the form natively. Retrying the press is cheaper and less
 * brittle than probing React internals for a hydration marker.
 */
async function openPalette(page: import("@playwright/test").Page) {
  const box = page.getByRole("combobox", { name: SEARCH_LABEL });
  await expect(async () => {
    await page.keyboard.press("Control+k");
    await expect(box).toHaveAttribute("aria-expanded", "true", { timeout: 1_000 });
  }).toPass({ timeout: 15_000 });
  return box;
}

test.describe("Search palette", () => {
  test("Ctrl+K opens it and typing finds a job", async ({
    authenticatedPage: page,
  }) => {
    const box = await openPalette(page);

    const palette = page.getByRole("listbox", { name: "Search results" });
    await expect(palette).toBeVisible();
    // An empty query fires nothing at all — the palette says so rather than
    // listing everything.
    await expect(palette.getByText(/Type to search across samples/)).toBeVisible();

    await box.fill("invoice");

    /* Three rows, not one: the sample, the job and the report fixtures all
     * describe the same file, so a hit under each group header is what proves
     * all three sources were queried and merged rather than one of them
     * carrying the result on its own. */
    await expect(
      palette.getByRole("option", { name: /invoice_scan\.exe/ })
    ).toHaveCount(3);
    for (const group of ["Samples", "Jobs", "Reports"]) {
      await expect(palette.getByText(group, { exact: true })).toBeVisible();
    }
    /* The banner is the point of this assertion. Each of the three sources is
     * caught independently, so a partial failure renders "Search is incomplete
     * — … could not be loaded." *alongside* whatever did load. A test that only
     * checked for a matching row would pass with two thirds of search dead. */
    await expect(palette.getByRole("alert")).toHaveCount(0);
  });

  test("reports a query with no matches instead of an empty box", async ({
    authenticatedPage: page,
  }) => {
    const box = page.getByRole("combobox", { name: SEARCH_LABEL });
    await box.click();
    await box.fill("nothing-matches-this");

    const palette = page.getByRole("listbox", { name: "Search results" });
    await expect(palette.getByText(/No matches for/)).toBeVisible();
    await expect(palette.getByRole("alert")).toHaveCount(0);
  });

  test("Escape closes it", async ({ authenticatedPage: page }) => {
    const box = await openPalette(page);

    await page.keyboard.press("Escape");
    await expect(box).toHaveAttribute("aria-expanded", "false");
    await expect(
      page.getByRole("listbox", { name: "Search results" })
    ).toHaveCount(0);
  });
});
