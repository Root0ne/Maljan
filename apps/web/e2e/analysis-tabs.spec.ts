import { alerts, test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT } from "./report-fixture";

/**
 * Every analysis tab, loaded once against one complete report.
 *
 * Only `/process` had coverage; the other eleven had never been rendered by a
 * test. That matters more here than on a list page, because there is **no error
 * boundary anywhere in `src/`** — a TypeError in one of these tabs is not a
 * caught error state, it takes the route down. The Summary tab in particular
 * dereferences `severity.rating`, `identity.hashes.sha256`, `attribution.family`
 * and `capabilities_narrative` with no guards.
 *
 * Each test asserts a heading that appears **only in the populated branch**.
 * The tabs all render a static shell plus one of {loading, "Analysis in
 * progress…", an empty-state sentence, real content}, and the shell is
 * identical in all four — so asserting on the shell would pass on a report that
 * arrived empty. `persistence` and `defense` have no such heading at all and
 * are asserted on their rendered items.
 *
 * Every test also checks for the layout's two error banners and for Next's dev
 * overlay, which is how an uncaught render error surfaces under `next dev`.
 */

interface Tab {
  /** Path suffix under /analysis/{id} */
  path: string;
  /** Something only the populated branch renders. */
  expect: (page: import("@playwright/test").Page) => Promise<void>;
}

const heading = (name: RegExp | string) => async (page: import("@playwright/test").Page) => {
  await expect(page.getByRole("heading", { name }).first()).toBeVisible();
};

const TABS: Tab[] = [
  { path: "", expect: heading(/Executive Summary/i) },
  { path: "/identity", expect: heading(/Sample Identification/i) },
  { path: "/static", expect: heading(/Imports/i) },
  { path: "/dynamic", expect: heading(/Process Tree/i) },
  { path: "/network", expect: heading(/Domains/i) },
  {
    path: "/persistence",
    // No heading in this tab — assert the mechanism itself.
    expect: async (page) => {
      await expect(page.getByText(/CurrentVersion\\?\\Run\\?\\UpdateSvc/)).toBeVisible();
    },
  },
  { path: "/capabilities", expect: heading(/MITRE ATT&CK Matrix/i) },
  { path: "/attribution", expect: heading(/Family Attribution/i) },
  { path: "/detection", expect: heading(/Generated detection rules/i) },
  {
    path: "/defense",
    // Also headingless; the recommendation text is the content.
    expect: async (page) => {
      await expect(
        page.getByText(/Hunt for WriteProcessMemory into non-child processes/)
      ).toBeVisible();
    },
  },
  { path: "/process", expect: heading(/Agent Transcript/i) },
];

test.describe("Analysis tabs", () => {
  test.beforeEach(async ({ sessionPage: page }) => {
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(REPORT),
      })
    );
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(COMPLETED_JOB),
      })
    );
  });

  for (const tab of TABS) {
    // One test per tab rather than one loop inside a single test, so a failure
    // names the tab instead of stopping the walk at the first broken one.
    test(`${tab.path || "/ (summary)"} renders its content`, async ({
      sessionPage: page,
    }) => {
      /* With no error boundary anywhere in the app, an unguarded property
       * access in one of these tabs surfaces as an uncaught exception rather
       * than as an error state, and React then unmounts the subtree — which can
       * leave a page that merely looks sparse. Collect them directly instead of
       * looking for Next's dev overlay: `nextjs-portal` is present on every dev
       * page whether or not anything went wrong. */
      const pageErrors: string[] = [];
      page.on("pageerror", (err) => pageErrors.push(err.message));

      await page.goto(`/analysis/${JOB_ID}${tab.path}`);
      await tab.expect(page);

      // The layout raises these when getJob or getReportByJobId fails.
      await expect(alerts(page)).toHaveCount(0);
      expect(pageErrors).toEqual([]);
    });
  }

  test("/attribution shows the byte markers that named the family", async ({
    sessionPage: page,
  }) => {
    /* Separate from the tab walk above, which only proves the tab rendered
     * *something*. This asserts the specific section that was missing until
     * 2026-07-28: `tool_artifact_matches` was produced by the pipeline and
     * printed in the markdown report, and the UI never read the field. It is
     * the only attribution source that works with the sandbox unreachable, so
     * its absence was worst exactly when it mattered most. */
    await page.goto(`/analysis/${JOB_ID}/attribution`);

    await expect(
      page.getByRole("heading", { name: /Offensive-Tool Artifacts \(1\)/i })
    ).toBeVisible();
    // `exact` matters: the tool cell says "AsyncRAT" and one of the markers is
    // "AsyncRAT_Config", so a substring match resolves to two nodes and trips
    // strict mode.
    await expect(page.getByText("AsyncRAT", { exact: true })).toBeVisible();
    await expect(page.getByText("AsyncRAT_Config")).toBeVisible();
  });

  test("/attribution shows all four evidence sources, not just the name", async ({
    sessionPage: page,
  }) => {
    /* The byte markers were one of four sibling fields on FamilyAttribution;
     * the other three were dead in exactly the same way. A family name with no
     * visible derivation is the failure this guards against — the tab used to
     * show a verdict and withhold every deterministic reason for it. */
    await page.goto(`/analysis/${JOB_ID}/attribution`);

    await expect(
      page.getByRole("heading", { name: /Function-Hash Matches/i })
    ).toBeVisible();
    await expect(page.getByText("sub_401A20")).toBeVisible();

    await expect(
      page.getByRole("heading", { name: /Family-Feature RAG Candidates/i })
    ).toBeVisible();
    await expect(page.getByText("FormBook")).toBeVisible();

    await expect(
      page.getByRole("heading", { name: /ATT&CK Case Priors/i })
    ).toBeVisible();
    await expect(page.getByText("T1055", { exact: true })).toBeVisible();
  });

  test("/live renders the running view", async ({ sessionPage: page }) => {
    /* Not in the table above because it is the one tab that needs the opposite
     * job state: on a completed run it deliberately says there is nothing live
     * to show. It also mounts a second WebSocket of its own on top of the
     * layout's, which is why the tab walk uses /process instead. */
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ...COMPLETED_JOB, status: "running", completed_at: null }),
      })
    );
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ status: 404, body: JSON.stringify({ detail: "Not found" }) })
    );

    await page.goto(`/analysis/${JOB_ID}/live`);

    await expect(page.getByRole("heading", { name: "Agent Status" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Event Log" })).toBeVisible();
    await expect(
      page.getByText(/Analysis already completed/)
    ).toHaveCount(0);
    await expect(alerts(page)).toHaveCount(0);
  });

  test("the LIVE tab is offered only while the job is running", async ({
    sessionPage: page,
  }) => {
    await page.goto(`/analysis/${JOB_ID}`);
    await expect(page.getByRole("link", { name: /^LIVE$/i })).toHaveCount(0);

    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ...COMPLETED_JOB, status: "running", completed_at: null }),
      })
    );
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ status: 404, body: JSON.stringify({ detail: "Not found" }) })
    );
    await page.goto(`/analysis/${JOB_ID}`);
    await expect(page.getByRole("link", { name: /^LIVE$/i })).toBeVisible();
  });

  /* The 2026-07-26 audit folded seven routes into three. They are kept as
   * redirect stubs precisely so bookmarks and links in already-issued reports do
   * not 404 — which is only true for as long as something checks.
   *
   * One test per redirect rather than a loop: seven navigations in a single test
   * overran the 30 s test timeout under `next dev`, which reads as a broken
   * redirect when it is only a slow first compile. */
  const REDIRECTS: [string, string][] = [
    ["/ttps", "/capabilities"],
    ["/agents", "/process"],
    ["/pipeline", "/process"],
    ["/timeline", "/process"],
    ["/rules", "/detection"],
    ["/signatures", "/detection"],
    ["/stix", "/detection"],
  ];

  for (const [from, to] of REDIRECTS) {
    test(`${from} still redirects to ${to}`, async ({ sessionPage: page }) => {
      await page.goto(`/analysis/${JOB_ID}${from}`);
      await expect(page).toHaveURL(new RegExp(`/analysis/${JOB_ID}${to}$`), {
        timeout: 20_000,
      });
    });
  }
});
