import { alerts, test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT, REPORT_ID } from "./report-fixture";

/**
 * Every analysis tab, loaded once against one complete report.
 *
 * Only the process tab had coverage; the other eleven had never been rendered by a
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
  // The typed "Sample Identification" block stands down when a header section
  // covers it, and the fixture has one — so the hashes are what this tab
  // always renders on a populated report, whichever half draws the rest.
  { path: "/identity", expect: heading(/File Hashes/i) },
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
  {
    path: "/conversation",
    // No heading of its own: the tab bar names it, and the stream is the
    // content. The recorded conversation is what a completed run draws.
    expect: async (page) => {
      await expect(page.getByTestId("conversation-stream")).toContainText(
        "Final verdict: Malicious.",
      );
    },
  },
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

  test("/attribution shows every evidence source, not just the name", async ({
    sessionPage: page,
  }) => {
    /* A family name with no visible derivation is the failure this guards
     * against — the tab used to show a verdict and withhold every reason for
     * it. */
    await page.goto(`/analysis/${JOB_ID}/attribution`);

    await expect(
      page.getByRole("heading", { name: /Function-Hash Matches/i })
    ).toBeVisible();
    await expect(page.getByText("sub_401A20")).toBeVisible();

    await expect(
      page.getByRole("heading", { name: /Family-Feature RAG Candidates/i })
    ).toBeVisible();
    await expect(page.getByText("FormBook")).toBeVisible();
  });

  /* C4 (dev audit 2026-09-06): the IOC, ATT&CK and timeline endpoints all
   * worked and no button anywhere opened them, so the only route to an IOC
   * list was the markdown report or a hand-written API call. */
  test("the export row offers the IOC, ATT&CK and timeline endpoints", async ({
    sessionPage: page,
  }) => {
    const asked: string[] = [];
    page.on("request", (r) => {
      const path = new URL(r.url()).pathname;
      if (/\/reports\/[^/]+\/(iocs|mitre|timeline)$/.test(path)) asked.push(path);
    });

    await page.goto(`/analysis/${JOB_ID}`);

    await page.getByRole("button", { name: "IOC list" }).click();
    await page.getByRole("button", { name: "MITRE ATT&CK" }).click();
    await page.getByRole("button", { name: "Timeline" }).click();

    await expect
      .poll(() => asked.length)
      .toBeGreaterThanOrEqual(3);
    expect(asked).toContain(`/api/v1/reports/${REPORT_ID}/iocs`);
    expect(asked).toContain(`/api/v1/reports/${REPORT_ID}/mitre`);
    expect(asked).toContain(`/api/v1/reports/${REPORT_ID}/timeline`);
    await expect(alerts(page)).toHaveCount(0);
  });

  /* C3 (dev audit 2026-09-06): nothing on the page said which analyst line-up
   * produced the report, so a narrow profile read as a full run — the
   * deterministic static layers appear either way. */
  test("a non-default profile is named in the header, with its analysts", async ({
    sessionPage: page,
  }) => {
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...REPORT,
          run_summary: {
            ...REPORT.run_summary,
            profile: { name: "lean", analysts: ["network"], custom: [] },
          },
        }),
      })
    );

    await page.goto(`/analysis/${JOB_ID}`);
    const badge = page.getByText("Profile: lean");
    await expect(badge).toBeVisible();
    await expect(badge).toHaveAttribute("title", "Analysts: network");
  });

  test("the default profile and an old report show no profile badge", async ({
    sessionPage: page,
  }) => {
    // The fixture's run_summary predates profiles entirely: no key at all.
    await page.goto(`/analysis/${JOB_ID}`);
    await expect(page.getByText(/^Profile:/)).toHaveCount(0);

    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...REPORT,
          run_summary: {
            ...REPORT.run_summary,
            profile: { name: "default", analysts: ["static", "dynamic", "network"], custom: [] },
          },
        }),
      })
    );
    await page.goto(`/analysis/${JOB_ID}`);
    await expect(page.getByText(/^Profile:/)).toHaveCount(0);
  });

  /* C2 (dev audit 2026-09-06): with no sandbox report this tab showed the
   * "not detonated" notice and nothing else, even on runs where the dynamic
   * analyst executed and reached a stated conclusion — a run that worked
   * looked exactly like one that never started. */
  test("/dynamic shows the analyst's claims alongside the sandbox notice", async ({
    sessionPage: page,
  }) => {
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...REPORT,
          malware_report: { ...REPORT.malware_report, dynamic: null },
          agent_findings: REPORT.agent_findings.map((f) =>
            f.agent_name === "dynamic"
              ? {
                  ...f,
                  status: "complete",
                  claims: [
                    {
                      claim: "The sample very likely detected the sandbox and exited early.",
                      evidence_ref: "no process activity recorded",
                      confidence: 0.6,
                    },
                  ],
                }
              : f
          ),
        }),
      })
    );

    await page.goto(`/analysis/${JOB_ID}/dynamic`);

    await expect(page.getByText(/may not have been detonated/)).toBeVisible();
    await expect(page.getByRole("heading", { name: "Analyst findings" })).toBeVisible();
    await expect(
      page.getByText("The sample very likely detected the sandbox and exited early.")
    ).toBeVisible();
    await expect(page.getByText("no process activity recorded")).toBeVisible();
  });

  test("the conversation is offered whatever state the job is in", async ({
    sessionPage: page,
  }) => {
    /* The tab bar used to change shape when a run finished: LIVE was offered
     * only while it ran, so leaving a completed run and coming back to it
     * landed somewhere structurally different. One tab answers both now. */
    await page.goto(`/analysis/${JOB_ID}`);
    await expect(page.getByRole("link", { name: /^CONVERSATION$/i })).toBeVisible();
    await expect(page.getByRole("link", { name: /^LIVE$/i })).toHaveCount(0);
    await expect(page.getByRole("link", { name: /^PROCESS$/i })).toHaveCount(0);

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
    await expect(page.getByRole("link", { name: /^CONVERSATION$/i })).toBeVisible();
  });

  /* Twelve routes folded into five. They are kept as redirect stubs precisely
   * so bookmarks and links in already-issued reports do not 404 — which is
   * only true for as long as something checks.
   *
   * One test per redirect rather than a loop: seven navigations in a single test
   * overran the 30 s test timeout under `next dev`, which reads as a broken
   * redirect when it is only a slow first compile. */
  const REDIRECTS: [string, string][] = [
    ["/ttps", "/capabilities"],
    ["/agents", "/conversation"],
    ["/pipeline", "/conversation"],
    ["/timeline", "/conversation"],
    ["/live", "/conversation"],
    ["/process", "/conversation"],
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

/**
 * A1 (dev audit 2026-09-06): a job id that does not exist.
 *
 * The API answers a clean 404 and the page used to call that an outage — "Could
 * not connect to the API. Please ensure the backend is running." — under a
 * header reading "Pending analysis", while the socket kept retrying a job the
 * REST call had already said does not exist. The socket is left unrouted here
 * (`webSocket: null`) precisely so an attempt to open one would show up as a
 * `websocket` event rather than being absorbed by the default handler.
 */
test.describe("Analysis page for an unknown job", () => {
  test.use({ mockOptions: { webSocket: null } });

  const MISSING = "00000000-0000-0000-0000-0000000000ff";

  test("a 404 shows a job-not-found state, no live socket and no pending header", async ({
    sessionPage: page,
  }) => {
    // `next dev` opens its own HMR socket on every page; only the analysis
    // socket is this test's business.
    const sockets: string[] = [];
    page.on("websocket", (ws) => {
      if (ws.url().includes("/ws/analysis/")) sockets.push(ws.url());
    });

    await page.route(`**/api/v1/jobs/${MISSING}`, (route) =>
      route.fulfill({
        status: 404,
        contentType: "application/json",
        body: JSON.stringify({ detail: "Job not found" }),
      })
    );

    await page.goto(`/analysis/${MISSING}`);

    await expect(page.getByRole("heading", { name: "Job not found" })).toBeVisible();
    await expect(page.getByRole("link", { name: /back to jobs/i })).toBeVisible();
    await expect(page.getByText(/Could not connect to the API/)).toHaveCount(0);
    await expect(page.getByText("Pending analysis")).toHaveCount(0);
    await expect(page.getByText(/Analysis in progress/)).toHaveCount(0);
    expect(sockets).toEqual([]);
  });

  test("a network failure still shows the connectivity banner", async ({
    sessionPage: page,
  }) => {
    await page.route(`**/api/v1/jobs/${MISSING}`, (route) =>
      route.abort("connectionrefused")
    );

    await page.goto(`/analysis/${MISSING}`);

    await expect(page.getByText(/Could not connect to the API/)).toBeVisible();
    await expect(page.getByRole("heading", { name: "Job not found" })).toHaveCount(0);
  });
});
