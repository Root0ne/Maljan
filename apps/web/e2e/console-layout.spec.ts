import type { Page } from "@playwright/test";

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
 * **A verdict and a severity that disagree say so.** Neither is overruled;
 * a remark under the header says they disagree in plain words, and run
 * quality names both, instead of presenting two confident contradictory
 * facts two cards apart.
 *
 * The widths are asserted against the *document*, not against a component:
 * what went wrong was always a parent, and `scrollWidth` versus the viewport
 * is the one measurement that catches it wherever it lives.
 */

const PHONE = { width: 375, height: 812 };

/**
 * How far past the viewport's right edge the widest element reaches.
 *
 * With `inScrollers`, an element inside a box that scrolls sideways itself (a
 * table in its own `overflow-x: auto` wrapper) is reachable and so not
 * counted; the wrapper is still measured, so the page itself may not be wider.
 */
async function widestOverflow(
  page: Page,
  { inScrollers = false }: { inScrollers?: boolean } = {},
): Promise<number> {
  return page.evaluate((skipScrolled) => {
    const limit = document.documentElement.clientWidth;
    /* The walk stops at `main`: its `overflow-y: auto` computes its overflow-x
     * to `auto` too, so counting it would excuse everything on the page. Only a
     * scroller strictly inside `main` counts, and only one that itself fits the
     * viewport, so a wide wrapper cannot excuse its own contents. */
    const scrolled = (node: Element) => {
      for (
        let up = node.parentElement;
        up && up !== document.body && up.tagName !== "MAIN";
        up = up.parentElement
      ) {
        const x = getComputedStyle(up).overflowX;
        if ((x === "auto" || x === "scroll") && up.getBoundingClientRect().right <= limit) {
          return true;
        }
      }
      return false;
    };
    let worst = 0;
    for (const node of Array.from(document.querySelectorAll("body *"))) {
      const box = (node as HTMLElement).getBoundingClientRect();
      if (box.width === 0 && box.height === 0) continue;
      if (skipScrolled && scrolled(node)) continue;
      worst = Math.max(worst, Math.round(box.right - limit));
    }
    return worst;
  }, inScrollers);
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

  for (const tab of ["/indicators", "/evidence/conversation", "/evidence", "/evidence/records"] as const) {
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
    await expect(page.getByRole("heading", { name: "Recent analyses" })).toBeVisible();

    await expect(page.getByText("Total Analyses")).toBeVisible();
    await expect(page.getByText("Avg Duration")).toBeVisible();
    expect(await widestOverflow(page)).toBeLessThanOrEqual(1);
  });

  /* `main` is on screen while the page still shows its loading skeleton, and
   * the skeleton is narrower than the page it becomes: measured then, a sample
   * table 355 px wide inside its scroller passes when the fetch is slow and
   * fails when it is fast. Each page is measured once its own data is drawn. */
  const loaded = {
    "/samples": (page: Page) => page.getByText(/^Samples\s—\s\d+ files?$/),
    "/jobs": (page: Page) => page.getByRole("region", { name: "Find an analysis" }),
    "/settings/profile": (page: Page) => page.getByLabel("Full Name"),
  } as const;

  for (const path of Object.keys(loaded) as (keyof typeof loaded)[]) {
    test(`${path} stays inside the viewport`, async ({ authenticatedPage: page }) => {
      await page.goto(path);
      await expect(page.locator("main")).toBeVisible();
      await expect(loaded[path](page)).toBeVisible();
      expect(await widestOverflow(page, { inScrollers: true })).toBeLessThanOrEqual(1);
    });
  }

  test("the scroller allowance still catches a wide element outside a scroller", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/samples");
    await expect(loaded["/samples"](page)).toBeVisible();
    expect(await widestOverflow(page, { inScrollers: true })).toBeLessThanOrEqual(1);

    // Wide and directly in main: the page really is wider, so it must count.
    await page.evaluate(() => {
      const box = document.createElement("div");
      box.id = "probe-wide";
      box.style.cssText = "width:900px;height:10px";
      document.querySelector("main")!.prepend(box);
    });
    expect(await widestOverflow(page, { inScrollers: true })).toBeGreaterThan(1);
    expect(await widestOverflow(page)).toBeGreaterThan(1);

    // The same width inside its own horizontal scroller is reachable.
    await page.evaluate(() => {
      const wrap = document.getElementById("probe-wide")!;
      wrap.style.cssText = "width:100%;height:10px;overflow-x:auto";
      const inner = document.createElement("div");
      inner.style.cssText = "width:900px;height:10px";
      wrap.append(inner);
    });
    expect(await widestOverflow(page, { inScrollers: true })).toBeLessThanOrEqual(1);
    expect(await widestOverflow(page)).toBeGreaterThan(1);
  });

  test("the analysis header and its tab strip fit", async ({ authenticatedPage: page }) => {
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ json: REPORT }),
    );
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({ json: COMPLETED_JOB }),
    );
    await page.goto(`/analysis/${JOB_ID}`);
    await expect(page.getByRole("navigation", { name: "Analysis sections" })).toBeVisible();

    // Every tab is reachable: the strip scrolls sideways inside itself
    // rather than pushing the page wider.
    const nav = page.getByRole("navigation", { name: "Analysis sections" });
    await expect(nav.getByRole("link")).toHaveCount(6);
    await nav.getByRole("link", { name: /^Evidence/ }).scrollIntoViewIfNeeded();
    await expect(nav.getByRole("link", { name: /^Evidence/ })).toBeInViewport();
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
    );
    expect(overflow).toBeLessThanOrEqual(1);
  });
});

test.describe("a verdict against its own severity", () => {
  test("names the disagreement once under the header, and both facts in run quality", async ({ authenticatedPage: page }) => {
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

    const remarks = page.getByRole("region", { name: "Remarks" });
    await expect(remarks.getByText(/verdict and the severity rating disagree/)).toHaveCount(1);
    await expect(remarks).not.toContainText("Judge");

    await page.goto(`/analysis/${JOB_ID}/evidence`);
    await page.getByRole("button", { name: /Run quality/ }).click();
    const notes = page.getByTestId("verdict-notes");
    await expect(notes.getByText("Judge: Malicious 0.95 · Severity: Informational")).toBeVisible();
    await expect(notes.getByText(/verdict and the severity rating of this run disagree/)).toBeVisible();
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

    const header = page.getByRole("region", { name: "Analysis summary" });
    await expect(header.getByRole("img", { name: "Malicious, confidence 91 percent" })).toHaveCount(1);
    // The filename is the heading and is not restated under it.
    await expect(page.getByText("Sample:")).toHaveCount(0);
    await expect(page.getByText(/Confidence: \d+\/100/)).toHaveCount(0);
    // Agreeing, nothing is remarked on.
    await expect(page.getByRole("region", { name: "Remarks" })).toHaveCount(0);
    // The verdict line as the run recorded it is in run quality.
    await page.goto(`/analysis/${JOB_ID}/evidence`);
    await page.getByRole("button", { name: /Run quality/ }).click();
    await expect(page.getByTestId("verdict-notes").getByText("Malicious · Confidence: 0.91")).toBeVisible();
  });

  test("says a fallback verdict was never assessed", async ({ authenticatedPage: page }) => {
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({ json: COMPLETED_JOB }),
    );
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ json: { ...REPORT, overall_confidence: null } }),
    );
    await page.goto(`/analysis/${JOB_ID}`);

    await expect(
      page.getByRole("region", { name: "Analysis summary" }).getByRole("img", { name: "Malicious, confidence not assessed" }),
    ).toBeVisible();
    await page.goto(`/analysis/${JOB_ID}/evidence`);
    await page.getByRole("button", { name: /Run quality/ }).click();
    await expect(page.getByTestId("verdict-notes").getByText("Malicious · Confidence: not assessed")).toBeVisible();
  });
});
