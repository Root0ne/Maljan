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

  test("the summary gives each stage's time, the same figure the strip prints", async ({
    sessionPage: page,
  }) => {
    await page.goto(`/analysis/${JOB_ID}`);
    const timing = page.getByRole("region", { name: "Time per stage" });
    await expect(timing).toBeVisible();
    await expect(timing).toContainText("Total elapsed: 29m 55s");

    const rows = timing.getByRole("listitem");
    // The declined debate took no time and has no row.
    await expect(rows).toHaveCount(3);
    const strip = page.getByTestId("pipeline-strip");
    for (const figure of ["42.0 s", "9.5 s", "2.1 s"]) {
      await expect(timing.getByText(figure, { exact: true })).toBeVisible();
      await expect(strip.getByText(figure, { exact: true })).toBeVisible();
    }
  });

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
  test("a run's Sigma section is drawn on DETECTION with its level and chips, and STATIC links there", async ({
    sessionPage: page,
  }) => {
    const sigma = {
      key: "sigma_matches",
      title: "Sigma rule matches",
      kind: "table" as const,
      columns: ["Rule", "Level", "Technique", "Matched fields"],
      rows: [["Run key persistence", "high", "T1547.001", "TargetObject=HKCU Run"]],
      text: "",
      items: [],
      evidence_ids: ["ev_0001"],
      source: "tool:sigma_match",
    };
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...REPORT,
          malware_report: {
            ...REPORT.malware_report!,
            sections: [...(REPORT.malware_report!.sections ?? []), sigma],
          },
        }),
      })
    );

    await page.goto(`/analysis/${JOB_ID}/detection`);
    await expect(page.getByText("Run key persistence")).toBeVisible();
    // The rule's own level, in words, on the ladder.
    await expect(page.locator("[data-rule-level]").first()).toContainText("High");
    // Each row still links to the ledger entry it came from.
    await expect(
      page.locator('[data-rule-provenance="sigma_matches"]').getByRole("link", { name: "ev_0001" })
    ).toHaveAttribute(
      "href",
      `/analysis/${JOB_ID}/evidence?evidence=ev_0001`
    );

    await page.goto(`/analysis/${JOB_ID}/static`);
    const moved = page.locator("[data-rules-moved]");
    await expect(moved.getByRole("link", { name: "DETECTION" })).toHaveAttribute(
      "href",
      `/analysis/${JOB_ID}/detection`
    );
    // Drawn once, on DETECTION, and not repeated here.
    await expect(page.getByRole("heading", { name: /Sigma rule matches/i })).toHaveCount(0);
  });

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

    await expect(page.getByText(/was not detonated on this run/)).toBeVisible();
    await expect(page.getByRole("heading", { name: "Analyst findings" })).toBeVisible();
    await expect(
      page.getByText("The sample very likely detected the sandbox and exited early.")
    ).toBeVisible();
    await expect(page.getByText("no process activity recorded")).toBeVisible();
  });

  /* The identity section is the one that overlaps the tab's own blocks: the
   * hashes it carries were printed twice on one screen, and its three signing
   * rows are one fact about one format with the tool's defaults beside it. */
  test("the identity table drops what the tab draws better", async ({
    sessionPage: page,
  }) => {
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...REPORT,
          malware_report: {
            ...REPORT.malware_report,
            sections: [
              {
                key: "identity",
                title: "Sample identity",
                kind: "kv",
                columns: ["Field", "Value"],
                rows: [
                  ["file type", "pe"],
                  ["mime type", ""],
                  ["md5", "5d41402abc4b2a76b9719d911017c592"],
                  ["sha256", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"],
                  ["authenticode", "present=no, subject=, issuer="],
                  ["apk", "present=no, schemes="],
                  ["macho", "present=no"],
                ],
                text: "",
                items: [],
                evidence_ids: ["ev_0001"],
                source: "tool:identify_file",
              },
            ],
          },
        }),
      })
    );

    await page.goto(`/analysis/${JOB_ID}/identity`);

    // One place for a hash, and it is the block with the copy buttons.
    await expect(page.getByText("5d41402abc4b2a76b9719d911017c592")).toHaveCount(1);
    await expect(page.getByRole("heading", { name: /File Hashes/i })).toBeVisible();

    // The routed format says whether the sample is signed, as a sentence; the
    // two formats it is not say nothing at all.
    await expect(page.getByText("Authenticode")).toBeVisible();
    await expect(page.getByText("Not signed")).toBeVisible();
    await expect(page.getByText(/present=no/)).toHaveCount(0);
    await expect(page.getByText("macho", { exact: true })).toHaveCount(0);

    // A hash no tool produced is absent rather than drawn as a dash.
    await expect(page.getByText("SHA-512")).toHaveCount(0);
    await expect(page.getByText("TLSH")).toHaveCount(0);
    await expect(page.getByText("SSDeep")).toHaveCount(0);

    await expect(alerts(page)).toHaveCount(0);
  });

  /* The console dropped the one reputation answer a run gets. It draws it
   * now, on the tab that holds the hash that was looked up, and only when the
   * ledger actually holds it — a configured service that was never asked
   * draws nothing. */
  test("the identity tab draws what VirusTotal answered about the hash", async ({
    sessionPage: page,
  }) => {
    await page.route(`**/api/v1/jobs/*/evidence**`, (route) => {
      const tool = new URL(route.request().url()).searchParams.get("tool");
      const entries =
        tool === "get_file_report"
          ? [
              {
                id: "9",
                entry_id: "ev_0042",
                stage: "triage",
                agent: "pipeline",
                server: "virustotal",
                tool: "get_file_report",
                ok: true,
                duration_ms: 310,
                seq: 42,
                args: { hash: "a".repeat(64) },
                output: "",
                structured: {
                  data: {
                    attributes: {
                      last_analysis_stats: { malicious: 42, suspicious: 3, undetected: 26 },
                      popular_threat_classification: {
                        suggested_threat_label: "trojan.formbook/injector",
                      },
                      first_submission_date: 1_600_000_000,
                    },
                  },
                },
                created_at: "2026-09-01T10:00:00Z",
              },
            ]
          : [];
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          job_id: JOB_ID,
          entries,
          total: entries.length,
          page: 1,
          page_size: 5,
        }),
      });
    });

    await page.goto(`/analysis/${JOB_ID}/identity`);

    const section = page.getByTestId("reputation-section");
    await expect(section).toBeVisible();
    await expect(section.getByRole("heading", { name: "VirusTotal" })).toBeVisible();
    await expect(section).toContainText("42");
    await expect(section).toContainText("/71");
    await expect(section).toContainText("trojan.formbook/injector");
    // The citation resolves into the ledger rather than restating the row.
    await expect(section.getByRole("link", { name: "ev_0042" })).toHaveAttribute(
      "href",
      `/analysis/${JOB_ID}/evidence?evidence=ev_0042`,
    );
    await expect(alerts(page)).toHaveCount(0);
  });

  test("a run that asked nobody about the hash draws no reputation section", async ({
    sessionPage: page,
  }) => {
    await page.goto(`/analysis/${JOB_ID}/identity`);

    await expect(page.getByRole("heading", { name: /File Hashes/i })).toBeVisible();
    await expect(page.getByTestId("reputation-section")).toHaveCount(0);
  });

  /* A tab is a promise that there is something behind it. The fixture report
   * fills every one of them, which is what the walk above proves; this is the
   * other half — a report that filled none of them offers none. */
  test("a report with nothing in it offers only the three that always answer", async ({
    sessionPage: page,
  }) => {
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...REPORT,
          mitre_techniques: [],
          stix_bundle: null,
          agent_findings: [],
          malware_report: {
            ...REPORT.malware_report,
            static: null,
            dynamic: null,
            network: null,
            persistence: [],
            ttp_mappings: [],
            capability_matrix: [],
            sections: [],
            detection_signatures: [],
            defensive_recommendations: [],
            stix_bundle_extended: {},
            attribution: {
              family: null,
              family_confidence: 0,
              family_grounded: true,
              actor: null,
              campaign: null,
              similar_samples: [],
            },
          },
        }),
      })
    );

    await page.goto(`/analysis/${JOB_ID}`);

    // The identity block is on every report, so IDENTITY joins the three.
    for (const label of ["SUMMARY", "CONVERSATION", "IDENTITY", "EVIDENCE"]) {
      await expect(page.getByRole("link", { name: new RegExp(`^${label}$`, "i") })).toBeVisible();
    }
    for (const label of [
      "STATIC",
      "DYNAMIC",
      "NETWORK",
      "PERSISTENCE",
      "ATTRIBUTION",
      "DETECTION",
      "DEFENSE",
    ]) {
      await expect(page.getByRole("link", { name: new RegExp(`^${label}$`, "i") })).toHaveCount(0);
    }
    await expect(alerts(page)).toHaveCount(0);
  });

  test("a running job offers the three that can answer before it finishes", async ({
    sessionPage: page,
  }) => {
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

    await expect(page.getByRole("link", { name: /^SUMMARY$/i })).toBeVisible();
    await expect(page.getByRole("link", { name: /^CONVERSATION$/i })).toBeVisible();
    await expect(page.getByRole("link", { name: /^EVIDENCE$/i })).toBeVisible();
    await expect(page.getByRole("link", { name: /^IDENTITY$/i })).toHaveCount(0);
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
