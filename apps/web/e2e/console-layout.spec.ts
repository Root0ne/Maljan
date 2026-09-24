import { test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT } from "./report-fixture";

/**
 * The three things the console walkthrough found wrong about its own shape.
 *
 * **Nothing is clipped without a way to reach it.** `main` is a flex item, so
 * its `min-width: auto` let it grow to its content's min-content width: the
 * Detection tab's Suricata block took it 1100 px past a 1440 px window and the
 * shell's `overflow:hidden` removed the rest, with no scrollbar anywhere.
 *
 * **The base layout is the phone layout.** At 375 px the dashboard kept four
 * stat columns of about sixty pixels each, the analysis page showed two and a
 * half of its ten tabs, and twenty-seven elements sat past the right edge of a
 * document that did not scroll horizontally to reach them.
 *
 * **A verdict and a severity that disagree say so.** Both are the judge's, so
 * neither is overruled; the header carries them in one line instead of
 * presenting two confident contradictory facts two cards apart.
 *
 * The widths are asserted against the *document*, not against a component:
 * what went wrong was always a parent, and `scrollWidth` versus the viewport
 * is the one measurement that catches it wherever it lives.
 */

const PHONE = { width: 375, height: 812 };

async function widestOverflow(page: import("@playwright/test").Page): Promise<number> {
  return page.evaluate(() => {
    const limit = document.documentElement.clientWidth;
    let worst = 0;
    for (const node of Array.from(document.querySelectorAll("body *"))) {
      const box = (node as HTMLElement).getBoundingClientRect();
      if (box.width === 0 && box.height === 0) continue;
      worst = Math.max(worst, Math.round(box.right - limit));
    }
    return worst;
  });
}

test.describe("nothing is cut off", () => {
  test.beforeEach(async ({ authenticatedPage: page }) => {
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ json: REPORT }),
    );
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({ json: COMPLETED_JOB }),
    );
  });

  for (const tab of ["/detection", "/conversation", "/evidence"] as const) {
    test(`${tab} scrolls its own wide content at 1280 px`, async ({
      authenticatedPage: page,
    }) => {
      await page.setViewportSize({ width: 1280, height: 900 });
      await page.goto(`/analysis/${JOB_ID}${tab}`);
      await expect(page.getByRole("navigation", { name: "Analysis sections" })).toBeVisible();

      // The document itself never grows: the shell is `overflow:hidden`, so a
      // document wider than the window is content nothing can reach.
      const main = page.locator("main");
      await expect
        .poll(async () => (await main.boundingBox())?.width ?? 0)
        .toBeLessThanOrEqual(1280);
      expect(await widestOverflow(page)).toBeLessThanOrEqual(1);
    });
  }
});

test.describe("at 375 px", () => {
  test.use({ viewport: PHONE });

  test("the dashboard stacks rather than clipping its stat labels", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/dashboard");
    await expect(page.getByRole("heading", { name: "Latest runs" })).toBeVisible();

    await expect(page.getByText("Total Analyses")).toBeVisible();
    await expect(page.getByText("Avg Duration")).toBeVisible();
    expect(await widestOverflow(page)).toBeLessThanOrEqual(1);
  });

  for (const path of ["/samples", "/jobs", "/settings/profile"] as const) {
    test(`${path} stays inside the viewport`, async ({ authenticatedPage: page }) => {
      await page.goto(path);
      await expect(page.locator("main")).toBeVisible();
      expect(await widestOverflow(page)).toBeLessThanOrEqual(1);
    });
  }

  test("the analysis header and its tab strip wrap", async ({ authenticatedPage: page }) => {
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ json: REPORT }),
    );
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({ json: COMPLETED_JOB }),
    );
    await page.goto(`/analysis/${JOB_ID}`);
    await expect(page.getByRole("navigation", { name: "Analysis sections" })).toBeVisible();

    // Every tab the run earned is reachable, not two and a half of them.
    await expect(page.getByRole("link", { name: /EVIDENCE/ })).toBeVisible();
    expect(await widestOverflow(page)).toBeLessThanOrEqual(1);
  });
});

test.describe("a verdict against its own severity", () => {
  test("names the disagreement once, in the header", async ({ authenticatedPage: page }) => {
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({ json: COMPLETED_JOB }),
    );
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({
        json: {
          ...REPORT,
          overall_confidence: 0.95,
          malware_report: {
            ...REPORT.malware_report!,
            severity: {
              ...REPORT.malware_report!.severity,
              rating: "Informational",
            },
          },
        },
      }),
    );
    await page.goto(`/analysis/${JOB_ID}`);

    await expect(
      page.getByText("Judge: Malicious 0.95 · Severity: Informational"),
    ).toBeVisible();
    await expect(page.getByText(/verdict and the severity rating of this run disagree/)).toBeVisible();
  });

  test("says confidence once, and only where it agrees", async ({
    authenticatedPage: page,
  }) => {
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({ json: COMPLETED_JOB }),
    );
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ json: REPORT }),
    );
    await page.goto(`/analysis/${JOB_ID}`);

    await expect(page.getByText("Malicious · Confidence: 0.91")).toBeVisible();
    // The filename is the heading and is not restated under it.
    await expect(page.getByText("Sample:")).toHaveCount(0);
    await expect(page.getByText(/Confidence: \d+\/100/)).toHaveCount(0);
  });

  test("says a fallback verdict was never assessed", async ({ authenticatedPage: page }) => {
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({ json: COMPLETED_JOB }),
    );
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ json: { ...REPORT, overall_confidence: null } }),
    );
    await page.goto(`/analysis/${JOB_ID}`);

    await expect(page.getByText("Confidence: not assessed")).toBeVisible();
  });
});
