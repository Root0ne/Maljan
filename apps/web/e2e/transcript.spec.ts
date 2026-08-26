import { alerts, test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT } from "./report-fixture";

/**
 * The agent transcript — the same conversation live and after the fact.
 *
 * The post-run path is the one that can silently rot, and it changed shape:
 * the backend now records every `agent_message` as it broadcasts it and stores
 * that list, so a replay is the recording rather than a reconstruction. These
 * tests hold that line. Two of them exist specifically because the *old*
 * rebuild could not produce what they assert — an agent speaking in more than
 * one round, and the sycophancy intervention — so if someone quietly reverts to
 * rebuilding from `agent_findings`, they fail.
 *
 * The fixture (`report-fixture.ts`) carries a two-round conversation: opening
 * positions, a mediator ruling, the sycophancy notice, a revision that disputes
 * a peer, and the verdict.
 */

const LIVE_EVENT = {
  type: "agent_message",
  ts: "2026-07-26T12:00:00Z",
  data: {
    speaker: "static",
    role: "analyst",
    round: 0,
    status: "complete",
    text: "1 evidence-backed claim from the static layer.",
    claims: [
      {
        claim: "Packed section detected",
        evidence_ref: ".text entropy 7.8",
        confidence: 0.8,
        technique_id: null,
      },
    ],
  },
};

test.describe("Agent transcript", () => {
  test.beforeEach(async ({ authenticatedPage }) => {
    await authenticatedPage.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(REPORT),
      })
    );
    await authenticatedPage.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(COMPLETED_JOB),
      })
    );
    /* TranscriptView back-fills the event stream on mount for *every* job, not
     * only running ones. Default it to "the stream has expired", which is the
     * normal state for a completed run older than the 24 h TTL — and the exact
     * condition the stored recording exists to survive. */
    await authenticatedPage.route(`**/api/v1/jobs/${JOB_ID}/events**`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ job_id: JOB_ID, events: [], count: 0 }),
      })
    );
  });

  test("replays the whole conversation, in order, with no live stream", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(`/analysis/${JOB_ID}/process`);

    await expect(
      page.getByRole("heading", { name: /agent transcript/i })
    ).toBeVisible();

    // Six recorded messages, and the header counts them.
    await expect(page.getByText(/6 messages/)).toBeVisible();

    /* Static speaks twice — an opening analysis and a revision. `.first()` is
     * not laziness here: two elements is the assertion. The old rebuild stored
     * one row per agent, so it could only ever render one. */
    await expect(page.getByText("Static", { exact: true })).toHaveCount(2);
    await expect(page.getByText("Dynamic", { exact: true })).toHaveCount(1);
    await expect(page.getByText("Mediator", { exact: true })).toHaveCount(1);
    await expect(page.getByText("Judge", { exact: true })).toHaveCount(1);

    // Round dividers, including the opening pass — which had none before.
    await expect(page.getByText("Initial analysis")).toBeVisible();
    await expect(page.getByText(/negotiation round\s*1/i)).toBeVisible();

    await expect(alerts(page)).toHaveCount(0);
  });

  test("shows the sycophancy intervention as a notice, not a participant", async ({
    authenticatedPage: page,
  }) => {
    /* This message was emitted live and persisted nowhere, so a day after a run
     * a manufactured consensus looked exactly like an earned one. It is also
     * the reason the extra round exists, which is why it is centred rather than
     * shown as a sixth agent making a claim. */
    await page.goto(`/analysis/${JOB_ID}/process`);

    await expect(page.getByText("Sycophancy detector")).toBeVisible();
    await expect(
      page.getByText(/converged without new evidence/i)
    ).toBeVisible();
  });

  test("a failed analyst is labelled, not shown as a silent 0%", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(`/analysis/${JOB_ID}/process`);
    await expect(page.getByText("failed", { exact: true }).first()).toBeVisible();
    await expect(page.getByText(/sandbox unreachable/i)).toBeVisible();
  });

  test("the verdict line uses the normalised label, never the raw backend value", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(`/analysis/${JOB_ID}/process`);
    await expect(page.getByText(/final verdict: malicious/i)).toBeVisible();
    await expect(page.getByText(/final verdict: malware/i)).toHaveCount(0);
  });

  test("expanding a message reveals the claim and the artefact it cites", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(`/analysis/${JOB_ID}/process`);

    // Evidence is the point of the panel — a claim with no artefact behind it
    // is exactly what the grounding rules exist to prevent.
    await page.getByRole("button", { name: /1 claim/ }).first().click();
    // exact: the headline also quotes the leading claim ("… Leading: Imports
    // VirtualAllocEx …"), so a substring match resolves to two elements.
    await expect(
      page.getByText("Imports VirtualAllocEx and WriteProcessMemory", {
        exact: true,
      })
    ).toBeVisible();
    await expect(page.getByText(/KERNEL32\.dll!VirtualAllocEx/)).toBeVisible();
    await expect(page.getByText("T1055", { exact: true })).toBeVisible();
  });

  test("a disputed peer claim is shown as a dispute", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(`/analysis/${JOB_ID}/process`);

    // The revision round is where agents answer each other; a dispute is the
    // one part of that exchange that says they did not simply defer.
    await page.getByRole("button", { name: /1 dispute/ }).click();
    await expect(page.getByText(/absence is not contradiction/i)).toBeVisible();
  });

  test("the full prose report is available, and collapsed by default", async ({
    authenticatedPage: page,
  }) => {
    /* The prose reached the database before this but could only be read as a
     * JSON dump, and the *revised* prose was never stored at all. It stays
     * behind a disclosure — several thousand characters inline would bury the
     * conversation the panel exists to show. */
    await page.goto(`/analysis/${JOB_ID}/process`);

    await expect(page.getByText(/consistent with packing/i)).toHaveCount(0);

    await page.getByRole("button", { name: /full report/ }).first().click();
    await expect(page.getByText(/consistent with packing/i)).toBeVisible();
  });

  test("a running job shows its transcript from the event stream", async ({
    authenticatedPage: page,
  }) => {
    /* Regression: the first cut of this view read only the persisted report,
     * which does not exist until a run finishes — so it announced "This run
     * recorded no agent findings" for the entire duration of every analysis
     * while the findings were already streaming in. */
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ status: 404, body: JSON.stringify({ detail: "Not found" }) })
    );
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ...COMPLETED_JOB, status: "running", completed_at: null }),
      })
    );
    await page.route(`**/api/v1/jobs/${JOB_ID}/events**`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ job_id: JOB_ID, events: [LIVE_EVENT], count: 1 }),
      })
    );

    await page.goto(`/analysis/${JOB_ID}/process`);

    await expect(
      page.getByText(/1 evidence-backed claim from the static layer/)
    ).toBeVisible();
    await expect(page.getByText(/recorded no agent findings/)).toHaveCount(0);
  });

  test("the stages filter hides the domain analysts", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(`/analysis/${JOB_ID}/process`);
    await page.getByRole("button", { name: "Stages" }).click();
    await expect(page.getByText("Mediator", { exact: true })).toBeVisible();
    await expect(page.getByText("Static", { exact: true })).toHaveCount(0);
  });
});
