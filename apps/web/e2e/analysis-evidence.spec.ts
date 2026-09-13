import { test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT } from "./report-fixture";
import { assertNoUnmockedCalls } from "./mocks";

/**
 * The evidence tab, which is the surface that makes the rest of the console
 * checkable.
 *
 * Every other tab now cites ledger ids, and a citation is only a citation if a
 * reader can follow it. What is exercised here is exactly that: the rows come
 * from the endpoint rather than from the report, the filters narrow on the
 * server, a row opens to show what the tool actually returned, and the deep
 * link a citation chip produces lands on the entry it names.
 */
test.beforeEach(async ({ authenticatedPage: page }) => {
  await page.route("**/api/v1/jobs/*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(COMPLETED_JOB),
    })
  );
  await page.route("**/api/v1/reports/job/*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(REPORT),
    })
  );
});

test("the ledger lists one row per tool call", async ({ authenticatedPage: page }) => {
  await page.goto(`/analysis/${JOB_ID}/evidence`);
  await expect(page.getByRole("heading", { name: /Evidence Ledger/i })).toBeVisible();
  for (const id of ["ev_0001", "ev_0002", "ev_0003", "ev_0004"]) {
    await expect(page.getByRole("button", { name: `Toggle ${id}` })).toBeVisible();
  }
  await expect(page.getByText("4 calls")).toBeVisible();
  assertNoUnmockedCalls(page);
});

test("a failed call is marked as one", async ({ authenticatedPage: page }) => {
  await page.goto(`/analysis/${JOB_ID}/evidence`);
  const row = page.locator("tr", { has: page.getByRole("button", { name: "Toggle ev_0003" }) });
  await expect(row.getByText("error", { exact: true })).toBeVisible();
});

test("filtering by agent narrows the ledger", async ({ authenticatedPage: page }) => {
  await page.goto(`/analysis/${JOB_ID}/evidence`);
  await expect(page.getByRole("button", { name: "Toggle ev_0002" })).toBeVisible();

  await page.getByLabel("Filter by agent").selectOption("static");
  await expect(page.getByRole("button", { name: "Toggle ev_0001" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Toggle ev_0002" })).toHaveCount(0);
  await expect(page.getByText("2 calls matching")).toBeVisible();

  await page.getByRole("button", { name: "Clear" }).click();
  await expect(page.getByRole("button", { name: "Toggle ev_0002" })).toBeVisible();
});

test("filtering by stage narrows the ledger", async ({ authenticatedPage: page }) => {
  await page.goto(`/analysis/${JOB_ID}/evidence`);
  await page.getByLabel("Filter by stage").selectOption("verdict");
  await expect(page.getByRole("button", { name: "Toggle ev_0003" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Toggle ev_0001" })).toHaveCount(0);
});

test("a row opens to the arguments, the output and the parsed result", async ({
  authenticatedPage: page,
}) => {
  await page.goto(`/analysis/${JOB_ID}/evidence`);
  await page.getByRole("button", { name: "Toggle ev_0001" }).click();
  await expect(page.getByRole("heading", { name: "Output" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Structured" })).toBeVisible();
  // The fixture output is well past the preview cap, so the disclosure has
  // something to hold back and says how much.
  await expect(page.getByRole("button", { name: /Show more \(\d+ more characters\)/ })).toBeVisible();
});

test("an entry that lost its output to the byte budget says so", async ({
  authenticatedPage: page,
}) => {
  await page.goto(`/analysis/${JOB_ID}/evidence`);
  await page.getByRole("button", { name: "Toggle ev_0004" }).click();
  await expect(page.getByText(/dropped to keep this agent inside its byte budget/i)).toBeVisible();
});

test("the deep link opens the entry it names", async ({ authenticatedPage: page }) => {
  await page.goto(`/analysis/${JOB_ID}/evidence?evidence=ev_0003`);
  await expect(page.getByRole("button", { name: "Toggle ev_0003" })).toHaveAttribute(
    "aria-expanded",
    "true"
  );
  await expect(page.getByText("upstream refused the lookup")).toBeVisible();
});

test("a citation chip on a report section links to its entry", async ({
  authenticatedPage: page,
}) => {
  await page.goto(`/analysis/${JOB_ID}/static`);
  const chip = page.getByRole("link", { name: "ev_0001" }).first();
  await expect(chip).toBeVisible();
  await chip.click();
  await expect(page).toHaveURL(/\/evidence\?evidence=ev_0001$/);
  await expect(page.getByRole("button", { name: "Toggle ev_0001" })).toHaveAttribute(
    "aria-expanded",
    "true"
  );
});

test("a section no tab draws is shown beside the ledger", async ({
  authenticatedPage: page,
}) => {
  await page.goto(`/analysis/${JOB_ID}/evidence`);
  await expect(page.getByRole("heading", { name: /Sections no tab draws/i })).toBeVisible();
  await expect(page.getByRole("heading", { name: /R2 analysis/i })).toBeVisible();
  await expect(page.getByText("fcn.00401000")).toBeVisible();
});

test("the identity tab draws the sections routed to it", async ({
  authenticatedPage: page,
}) => {
  await page.goto(`/analysis/${JOB_ID}/identity`);
  await expect(page.getByRole("heading", { name: /PE header/i })).toBeVisible();
  await expect(page.getByText("0x14c")).toBeVisible();
  // The typed identity block stands down where a header section covers it,
  // and the hashes stay, because no section carries them.
  await expect(page.getByRole("heading", { name: /Sample Identification/i })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: /File Hashes/i })).toBeVisible();
});

test("a section covering a typed panel replaces it rather than repeating it", async ({
  authenticatedPage: page,
}) => {
  await page.goto(`/analysis/${JOB_ID}/static`);
  // The section is drawn...
  await expect(page.getByRole("heading", { name: /PE imports/i })).toBeVisible();
  // ...and the extractor's own Imports table is not, because it would be the
  // same import list a second time.
  await expect(page.getByRole("heading", { name: /^Imports \(/ })).toHaveCount(0);
});

test("the process tab draws the run as its stages", async ({ authenticatedPage: page }) => {
  await page.goto(`/analysis/${JOB_ID}/process`);
  await page.getByRole("button", { name: "Pipeline" }).click();
  await expect(page.getByRole("heading", { name: "Stages" })).toBeVisible();
  await expect(page.getByText("analysis", { exact: true }).first()).toBeVisible();
  // The stage that declined names the condition it failed, rather than being
  // left out of the list.
  await expect(
    page.getByText("condition not met: stages.analysis.claim_count > 3", { exact: true })
  ).toBeVisible();
});
