import { alerts, test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT } from "./report-fixture";

/**
 * The Conversation tab, against a feed the test owns.
 *
 * This is the view that replaced the LIVE and PROCESS pair, so it carries
 * their coverage as well as its own: a run replays from the recorded feed, a
 * run recorded before that feed existed still reads as a conversation, every
 * kind of line is drawn as the thing it is, and leaving the analysis for the
 * home page and coming back neither empties the view nor re-reads the run.
 *
 * Everything is mocked, including the socket, and the events below carry the
 * publisher's `seq` because that number is what the store orders and dedupes
 * on.
 */

const ROSTER = {
  agents: [
    { key: "lead", label: "Lead analyst", role: "analyst", stages: ["analysis"] },
    { key: "ahmet", label: "Ahmet", role: "analyst", stages: [], via: ["lead"] },
    { key: "judge", label: "Judge", role: "judge", stages: ["verdict"] },
  ],
  stages: [
    { key: "analysis", label: "Analysis", kind: "analysis", agents: ["lead"] },
    { key: "verdict", label: "Verdict", kind: "verdict", agents: ["judge"] },
  ],
};

const TS = "2026-09-17T12:00:00Z";

function event(type: string, data: Record<string, unknown>) {
  return { type, data, ts: TS };
}

const FEED = [
  event("roster", { seq: 1, ...ROSTER }),
  event("stage_started", { seq: 2, stage: "analysis", kind: "analysis", agents: ["lead"] }),
  event("tool_call_started", {
    seq: 3,
    stage: "analysis",
    agent: "lead",
    tool: "afl",
    server: "radare2",
    args_summary: "list functions",
  }),
  event("tool_call_finished", {
    seq: 4,
    stage: "analysis",
    agent: "lead",
    tool: "afl",
    server: "radare2",
    evidence_id: "ev_0007",
    ok: true,
    duration_ms: 812,
    summary: "41 functions, 3 imports of interest",
  }),
  event("validation_feedback", {
    seq: 5,
    stage: "analysis",
    agent: "lead",
    code: "claim_without_evidence",
    message: "Cite the call behind the injection claim.",
    retry_index: 1,
  }),
  event("agent_message", {
    seq: 6,
    stage: "analysis",
    speaker: "lead",
    display_name: "Lead analyst",
    role: "analyst",
    round: 0,
    status: "complete",
    kind: "says",
    confidence: 0.9,
    text: "1 evidence-backed claim from the static layer.",
    claims: [
      {
        claim: "Imports VirtualAllocEx and WriteProcessMemory",
        evidence_ref: "IAT: KERNEL32.dll!VirtualAllocEx",
        confidence: 0.9,
        technique_id: "T1055",
      },
    ],
    report: "STATIC ANALYSIS\n\nThe .text section entropy is consistent with packing.",
  }),
  event("agent_message", {
    seq: 7,
    stage: "analysis",
    speaker: "lead",
    display_name: "Lead analyst",
    role: "analyst",
    round: 0,
    kind: "delegation_ask",
    addressed_to: "ahmet",
    status: "complete",
    text: "Check whether those imports are resolved at runtime.",
  }),
  event("agent_message", {
    seq: 8,
    stage: "analysis",
    speaker: "ahmet",
    display_name: "Ahmet",
    role: "analyst",
    round: 0,
    kind: "delegation_answer",
    addressed_to: "lead",
    status: "complete",
    text: "They are resolved in the first second of execution.",
  }),
  event("stage_finished", { seq: 9, stage: "analysis", kind: "analysis", duration_ms: 4200 }),
  event("stage_skipped", { seq: 10, stage: "debate", kind: "debate", reason: "one analyst reported" }),
  event("stage_started", { seq: 11, stage: "verdict", kind: "verdict", agents: ["judge"] }),
  event("judge_question", {
    seq: 12,
    stage: "verdict",
    text: "Which call shows the injection pair being used.",
    addressed_to: "lead",
  }),
  event("agent_message", {
    seq: 13,
    stage: "verdict",
    speaker: "judge",
    display_name: "Judge",
    role: "judge",
    round: 0,
    kind: "verdict",
    status: "complete",
    text: "Final verdict: Malicious.",
  }),
];

/** Answer the run's feed, and count how many times it is asked for. */
async function mockRun(
  page: import("@playwright/test").Page,
  options: {
    events?: typeof FEED;
    status?: string;
    report?: unknown;
    roster?: unknown;
    onEventsRequest?: () => void;
  } = {},
) {
  await page.route(`**/api/v1/jobs/${JOB_ID}/events**`, (route) => {
    options.onEventsRequest?.();
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        job_id: JOB_ID,
        events: options.events ?? FEED,
        count: (options.events ?? FEED).length,
      }),
    });
  });
  await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        ...COMPLETED_JOB,
        status: options.status ?? COMPLETED_JOB.status,
        roster: options.roster === undefined ? ROSTER : options.roster,
      }),
    }),
  );
  await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
    options.report === null
      ? route.fulfill({ status: 404, body: JSON.stringify({ detail: "Not found" }) })
      : route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify(options.report ?? REPORT),
        }),
  );
}

const stream = (page: import("@playwright/test").Page) =>
  page.getByTestId("conversation-stream");

test.describe("Conversation", () => {
  test("replays the run as one conversation, grouped by stage", async ({
    sessionPage: page,
  }) => {
    await mockRun(page);
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    const feed = stream(page);
    await expect(feed).toContainText("1 evidence-backed claim from the static layer.");
    await expect(feed).toContainText("Final verdict: Malicious.");

    // Named by the label an operator gave each agent, not by its registry key.
    await expect(feed.getByText("Lead analyst").first()).toBeVisible();
    await expect(feed).not.toContainText("lead_1");

    // The stages, in the order they happened, with the reason the skipped one
    // gave rather than an empty gap.
    await expect(feed).toContainText("Analysis");
    await expect(feed).toContainText("Verdict");
    await expect(feed).toContainText("one analyst reported");

    await expect(alerts(page)).toHaveCount(0);
  });

  /* The per-agent results table sits one scroll under the participants strip
   * and the header strip, and drew the registry key where both of those draw
   * the operator's label — the same three agents, named two ways on one
   * screen. */
  test("the agents table names an agent the way the strip above it does", async ({
    sessionPage: page,
  }) => {
    const roster = {
      agents: [
        { key: "ahmet_1", label: "Ahmet", role: "static", stages: ["analysis"] },
        { key: "mehmet", label: "Mehmet", role: "dynamic", stages: ["analysis"] },
      ],
      stages: [
        {
          key: "analysis",
          label: "First pass",
          kind: "analysis",
          agents: ["ahmet_1", "mehmet"],
        },
      ],
    };
    await mockRun(page, {
      roster,
      report: {
        ...REPORT,
        run_summary: {
          ...REPORT.run_summary,
          stages: [
            {
              key: "analysis",
              kind: "analysis",
              ran: true,
              reason: "",
              agents: ["ahmet_1", "mehmet"],
              duration_ms: 1000,
            },
          ],
        },
        agent_findings: [
          {
            agent_name: "ahmet_1",
            domain: "static",
            claims: [{ claim: "Imports VirtualAllocEx", confidence: 0.9 }],
            dissent_items: [],
            revision_rounds: 0,
            final_confidence: 0.9,
            status: "complete",
            status_reason: null,
          },
          {
            agent_name: "mehmet",
            domain: "dynamic",
            claims: [],
            dissent_items: [],
            revision_rounds: 0,
            final_confidence: 0,
            status: "failed",
            status_reason: "sandbox unreachable",
          },
        ],
      },
    });
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    const table = page.getByRole("table");
    await expect(table).toContainText("Ahmet");
    await expect(table).toContainText("Mehmet");
    await expect(table).toContainText("stage First pass");
    // Never the slug the pipeline keys the second Ahmet by.
    await expect(table).not.toContainText("ahmet_1");
    await expect(alerts(page)).toHaveCount(0);
  });

  test("a run whose roster names nobody falls back to the key", async ({
    sessionPage: page,
  }) => {
    /* Neither the job nor the feed carries a roster, which is every run
     * recorded before the pipeline published one. */
    await mockRun(page, {
      roster: null,
      events: FEED.filter((e) => e.type !== "roster"),
    });
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    // The fixture's findings are keyed `static` and `dynamic`, and with no
    // roster those keys are all the table has.
    const table = page.getByRole("table");
    await expect(table).toContainText("static");
    await expect(table).toContainText("dynamic");
    await expect(table).toContainText("stage analysis");
  });

  test("draws a tool call as one line that opens the ledger row", async ({
    sessionPage: page,
  }) => {
    await mockRun(page);
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    const feed = stream(page);
    await expect(feed).toContainText("radare2.afl");
    await expect(feed).toContainText("41 functions, 3 imports of interest");

    const chip = feed.getByRole("link", { name: "ev_0007" });
    await expect(chip).toBeVisible();
    await chip.click();
    await page.waitForURL(`**/analysis/${JOB_ID}/evidence?evidence=ev_0007`);
  });

  test("draws a correction, a question and a delegated pair as themselves", async ({
    sessionPage: page,
  }) => {
    await mockRun(page);
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    const feed = stream(page);
    await expect(feed).toContainText("claim_without_evidence");
    await expect(feed).toContainText("Cite the call behind the injection claim.");
    await expect(feed).toContainText("Which call shows the injection pair being used.");
    await expect(feed).toContainText("Check whether those imports are resolved at runtime.");
    await expect(feed).toContainText("They are resolved in the first second of execution.");
  });

  test("keeps the claims and the prose behind a disclosure", async ({
    sessionPage: page,
  }) => {
    await mockRun(page);
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    const feed = stream(page);
    await expect(feed).not.toContainText("KERNEL32.dll!VirtualAllocEx");
    await expect(feed).not.toContainText("consistent with packing");

    await feed.getByRole("button", { name: /1 claim/ }).click();
    await expect(feed).toContainText("Imports VirtualAllocEx and WriteProcessMemory");
    await expect(feed).toContainText("KERNEL32.dll!VirtualAllocEx");
    await expect(feed).toContainText("T1055");

    await feed.getByRole("button", { name: /full report/ }).click();
    await expect(feed).toContainText("consistent with packing");
  });

  test("narrows to one agent and to one kind of line", async ({ sessionPage: page }) => {
    await mockRun(page);
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    const feed = stream(page);
    await page.getByRole("button", { name: /Ahmet/ }).click();
    await expect(feed).toContainText("They are resolved in the first second of execution.");
    await expect(feed).not.toContainText("Final verdict: Malicious.");

    await page.getByRole("button", { name: "Clear filters" }).click();
    await expect(feed).toContainText("Final verdict: Malicious.");

    await page.getByRole("button", { name: "Tool calls" }).click();
    await expect(feed).toContainText("radare2.afl");
    await expect(feed).not.toContainText("Final verdict: Malicious.");
  });

  test("survives leaving the analysis and coming back", async ({ sessionPage: page }) => {
    let reads = 0;
    await mockRun(page, { onEventsRequest: () => (reads += 1) });
    await page.goto(`/analysis/${JOB_ID}/conversation`);
    await expect(stream(page)).toContainText("Final verdict: Malicious.");
    expect(reads).toBe(1);

    await page.getByRole("link", { name: "Dashboard" }).click();
    await page.waitForURL("**/dashboard");
    await page.goBack();
    await page.waitForURL(`**/analysis/${JOB_ID}/conversation`);

    await expect(stream(page)).toContainText("Final verdict: Malicious.");
    expect(reads).toBe(1);
  });

  test("opens one socket for the run, whatever tab is read", async ({
    sessionPage: page,
  }) => {
    let sockets = 0;
    await page.routeWebSocket("**/ws/analysis/**", () => {
      sockets += 1;
    });
    await mockRun(page, { status: "running", report: null });

    await page.goto(`/analysis/${JOB_ID}/conversation`);
    await expect(stream(page)).toContainText("Final verdict: Malicious.");
    await page.getByRole("link", { name: "EVIDENCE" }).click();
    await page.waitForURL(`**/analysis/${JOB_ID}/evidence`);

    expect(sockets).toBe(1);
  });

  test("reads a run recorded before the event feed existed", async ({
    sessionPage: page,
  }) => {
    await mockRun(page, { events: [] });
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    const feed = stream(page);
    // The stored conversation, including the intervention that exists nowhere
    // else and an analyst that spoke in two rounds.
    await expect(feed).toContainText("Sycophancy detector");
    await expect(feed).toContainText("converged without new evidence");
    await expect(feed).toContainText("Injection pair confirmed against the packed section");
    await expect(feed).toContainText("Final verdict: Malicious.");
  });

  test("says what a run with nothing recorded has", async ({ sessionPage: page }) => {
    await mockRun(page, { events: [], report: { ...REPORT, transcript: [] } });
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    await expect(stream(page)).toContainText("passed the retention window");
  });

  test("the retired routes land on the conversation", async ({ sessionPage: page }) => {
    await mockRun(page);
    for (const retired of ["live", "process", "agents", "pipeline", "timeline"]) {
      await page.goto(`/analysis/${JOB_ID}/${retired}`);
      await page.waitForURL(`**/analysis/${JOB_ID}/conversation`);
    }
    await expect(stream(page)).toContainText("Final verdict: Malicious.");
  });

  test("the run's shape is on the header, and only there", async ({
    sessionPage: page,
  }) => {
    await mockRun(page);
    await page.goto(`/analysis/${JOB_ID}/conversation`);

    const strip = page.getByTestId("pipeline-strip");
    // The roster's label for the stage, and the label of the agent that ran
    // in it — the same names the conversation draws, not the keys.
    await expect(strip).toContainText("Analysis");
    await expect(strip).toContainText("Lead analyst");
    await expect(strip).toContainText("done");
    await expect(page.getByTestId("pipeline-strip")).toHaveCount(1);
  });
});
