import { test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT } from "./report-fixture";

/**
 * The Evidence tab opens on the evidence bundle: the record behind the
 * analyst report, readable in the console with the same anchors as the
 * bundle's own HTML (`MOCK_EVIDENCE_BUNDLE` in mocks.ts).
 */
test.beforeEach(async ({ authenticatedPage: page }) => {
  await page.route("**/api/v1/jobs/*", (route) => route.fulfill({ json: COMPLETED_JOB }));
  await page.route("**/api/v1/reports/job/*", (route) => route.fulfill({ json: REPORT }));
});

const EVIDENCE = `/analysis/${JOB_ID}/evidence`;

test("the tab opens on the bundle, with its sections listed and run quality folded", async ({
  authenticatedPage: page,
}) => {
  await page.goto(EVIDENCE);
  const views = page.getByRole("navigation", { name: "Evidence views" });
  await expect(views.getByRole("link", { name: "Evidence bundle" })).toHaveAttribute("aria-current", "page");
  const nav = page.getByRole("navigation", { name: "Bundle sections" });
  await expect(nav.getByRole("link")).toHaveText([
    "About this bundle",
    "Technical analysis",
    "Observed behaviour",
    "Evidence index4",
    "Notes cited by the analyst report2",
  ]);
  await expect(page.getByRole("heading", { name: "About this bundle" })).toBeVisible();
  await expect(page.getByRole("button", { name: /Run quality/ })).toHaveAttribute("aria-expanded", "false");
});

test("a section's Markdown is drawn as text, with links only where the report makes them", async ({
  authenticatedPage: page,
}) => {
  await page.goto(`${EVIDENCE}#sec-technical-analysis`);
  const bundle = page.getByTestId("evidence-bundle");
  await expect(bundle.getByRole("heading", { name: "Technical analysis" })).toBeVisible();
  // Markup in the report's text is shown, never run.
  const written = bundle.getByText(/window\.__bundleXss = 1/);
  await expect(written).toBeVisible();
  await expect(written).toContainText("script>window");
  expect(await page.evaluate(() => (window as unknown as { __bundleXss?: number }).__bundleXss)).toBeUndefined();
  await expect(bundle.locator("script, img")).toHaveCount(0);
  // A web link opens apart from the console; a script target is no link.
  await expect(bundle.getByRole("link", { name: "the technique" })).toHaveAttribute("rel", "noopener noreferrer nofollow");
  await expect(bundle.getByRole("link", { name: "a trap" })).toHaveCount(0);
  await expect(bundle.locator('a[href^="javascript:"]')).toHaveCount(0);
  // A table cell keeps its escaped pipe; a listing keeps its text.
  await expect(bundle.getByRole("cell", { name: "a|b" })).toBeVisible();
  await expect(bundle.getByText("pid=85 ppid=56 rundll32.exe")).toBeVisible();
  // A subsection has the bundle's anchor; the second use of a title is numbered.
  await expect(bundle.locator("#sec-packing-obfuscation-and-anti-analysis")).toBeVisible();
  await expect(bundle.locator("#sec-process-tree")).toBeVisible();
});

test("every anchor of the bundle deep-links", async ({ authenticatedPage: page }) => {
  // A subsection opens the section it is in.
  await page.goto(`${EVIDENCE}#sec-process-tree-2`);
  await expect(page.getByRole("heading", { name: "Observed behaviour", level: 2 })).toBeVisible();
  await expect(page.locator("#sec-process-tree-2")).toBeInViewport();

  // An evidence id opens the index on its row.
  await page.goto(`${EVIDENCE}#ev_0003`);
  const row = page.locator("tr#ev_0003");
  await expect(row).toBeVisible();
  await expect(row).toHaveClass(/bg-accent/);
  await expect(row).toContainText("failed");

  // A note opens the notes on that note; an id the index lacks is said so.
  await page.goto(`${EVIDENCE}#cite-2`);
  const note = page.locator("li#cite-2");
  await expect(note).toContainText("Note 2");
  await expect(note).toContainText("ev_0099 (not in the index)");
  // Its ids lead back to the index.
  await note.getByRole("link", { name: "ev_0003" }).click();
  await expect(page).toHaveURL(/#ev_0003$/);
  await expect(page.locator("tr#ev_0003")).toBeVisible();
});

test("the index is searched and filtered, and each row's output is one link away", async ({
  authenticatedPage: page,
}) => {
  await page.goto(`${EVIDENCE}#sec-evidence-index`);
  const bundle = page.getByTestId("evidence-bundle");
  await expect(bundle.getByText("4 calls", { exact: true })).toBeVisible();

  await bundle.getByLabel("Search the index").fill("strings");
  await expect(bundle.getByText("1 of 4 calls match")).toBeVisible();
  await expect(bundle.locator("tbody tr")).toHaveCount(1);

  await bundle.getByLabel("Search the index").fill("");
  await bundle.getByLabel("Result").selectOption("failed");
  await expect(bundle.locator("tbody tr")).toHaveCount(1);
  await expect(bundle.locator("tr#ev_0003")).toBeVisible();

  await bundle.getByLabel("Result").selectOption("all");
  await bundle.getByLabel("Agent").selectOption("static");
  await expect(bundle.locator("tbody tr")).toHaveCount(2);
  await bundle.getByRole("button", { name: "Clear filters" }).click();
  await expect(bundle.locator("tbody tr")).toHaveCount(4);

  await bundle.getByRole("link", { name: "Output of ev_0003" }).click();
  await expect(page).toHaveURL(/\/evidence\/records\?evidence=ev_0003$/);
  await expect(page.getByRole("button", { name: "Toggle ev_0003" })).toHaveAttribute("aria-expanded", "true");
});

test("a record link written before the bundle keeps its query and fragment on Records", async ({
  authenticatedPage: page,
}) => {
  await page.goto(`${EVIDENCE}?evidence=ev_0003&view=full#output`);
  await expect(page).toHaveURL(/\/evidence\/records\?evidence=ev_0003&view=full#output$/);
  await expect(page.getByRole("button", { name: "Toggle ev_0003" })).toHaveAttribute("aria-expanded", "true");
});

test("a bundle the server cannot give says so, and the records stay one link away", async ({
  authenticatedPage: page,
}) => {
  await page.route("**/api/v1/reports/*/evidence-bundle.json", (route) =>
    route.fulfill({ status: 500, json: { detail: "the bundle could not be rendered" } })
  );
  await page.goto(EVIDENCE);
  const alert = page.getByTestId("analysis-content").getByRole("alert");
  await expect(alert).toContainText("The evidence bundle could not be read");
  await alert.getByRole("link", { name: "Records" }).click();
  await expect(page).toHaveURL(`${EVIDENCE}/records`);
});

test.describe("at 390 px", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("the bundle never scrolls sideways, and a picker replaces the navigator", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(EVIDENCE);
    await expect(page.getByRole("navigation", { name: "Bundle sections" })).toBeHidden();
    await page.getByRole("combobox", { name: /^Section/ }).selectOption("sec-technical-analysis");
    await expect(page).toHaveURL(/#sec-technical-analysis$/);
    await expect(page.getByRole("heading", { name: "Technical analysis", level: 2 })).toBeVisible();
    const wide = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(wide).toBeLessThanOrEqual(1);
    await page.getByRole("combobox", { name: /^Section/ }).selectOption("sec-evidence-index");
    await expect(page.locator("tr#ev_0001")).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1);
  });
});
