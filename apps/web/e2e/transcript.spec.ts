import { test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT } from "./report-fixture";

/**
 * The agent transcript — the same panel live and after the fact.
 *
 * These drive the post-run path, because it is the one that can silently rot:
 * it reconstructs the conversation from `agent_findings` and `negotiation_log`
 * rather than replaying events, so a schema change breaks it without breaking
 * the live feed.
 *
 * The payload comes from `report-fixture.ts` rather than an inline literal, so
 * this spec and the tab walk assert against the same report and `tsc` checks
 * both against the real DTO. The fixture is a superset of what this file needs;
 * the transcript reads only `agent_findings`, `negotiation_log` and `verdict`.
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
     * only running ones. This used to be mocked inside the one running-job test,
     * so the other five back-filled from the real API — and on a finished job a
     * successful back-fill is indistinguishable from an empty one, which is why
     * nothing looked wrong. Default it here to "the stream has expired", the
     * normal state for a completed run older than the 24 h TTL. */
    await authenticatedPage.route(`**/api/v1/jobs/${JOB_ID}/events**`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ job_id: JOB_ID, events: [], count: 0 }),
      })
    );
  });

  test("opens on the transcript and lists every speaker in order", async ({
    authenticatedPage,
  }) => {
    await authenticatedPage.goto(`/analysis/${JOB_ID}/process`);

    await expect(
      authenticatedPage.getByRole("heading", { name: /agent transcript/i })
    ).toBeVisible();

    // Analysts, then the mediator round, then the verdict.
    await expect(authenticatedPage.getByText("Static", { exact: true })).toBeVisible();
    await expect(authenticatedPage.getByText("Dynamic", { exact: true })).toBeVisible();
    await expect(authenticatedPage.getByText("Mediator", { exact: true })).toBeVisible();
    await expect(authenticatedPage.getByText(/negotiation round\s*1/i)).toBeVisible();
  });

  test("a failed analyst is labelled, not shown as a silent 0%", async ({
    authenticatedPage,
  }) => {
    await authenticatedPage.goto(`/analysis/${JOB_ID}/process`);
    await expect(authenticatedPage.getByText("failed", { exact: true }).first()).toBeVisible();
    await expect(authenticatedPage.getByText(/sandbox unreachable/i)).toBeVisible();
  });

  test("the verdict line uses the normalised label, never the raw backend value", async ({
    authenticatedPage,
  }) => {
    await authenticatedPage.goto(`/analysis/${JOB_ID}/process`);
    await expect(authenticatedPage.getByText(/final verdict: malicious/i)).toBeVisible();
    await expect(authenticatedPage.getByText(/final verdict: malware/i)).toHaveCount(0);
  });

  test("expanding a message reveals the claim and the artefact it cites", async ({
    authenticatedPage,
  }) => {
    await authenticatedPage.goto(`/analysis/${JOB_ID}/process`);

    // Evidence is the point of the panel — a claim with no artefact behind it
    // is exactly what the grounding rules exist to prevent.
    await authenticatedPage.getByRole("button", { name: /1 claim/ }).first().click();
    // exact: the headline also quotes the leading claim ("… Leading: Imports
    // VirtualAllocEx …"), so a substring match resolves to two elements.
    await expect(
      authenticatedPage.getByText("Imports VirtualAllocEx and WriteProcessMemory", {
        exact: true,
      })
    ).toBeVisible();
    await expect(
      authenticatedPage.getByText(/KERNEL32\.dll!VirtualAllocEx/)
    ).toBeVisible();
    await expect(authenticatedPage.getByText("T1055", { exact: true })).toBeVisible();
  });

  test("a running job shows its transcript from the event stream", async ({
    authenticatedPage,
  }) => {
    /* Regression: the first cut of this view read only the persisted report,
     * which does not exist until a run finishes — so it announced "This run
     * recorded no agent findings" for the entire duration of every analysis
     * while the findings were already streaming in. */
    await authenticatedPage.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ status: 404, body: JSON.stringify({ detail: "Not found" }) })
    );
    await authenticatedPage.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          id: JOB_ID,
          status: "running",
          sample_id: "99999999-8888-7777-6666-555555555555",
          sample_filename: "evil.exe",
          created_at: "2026-07-26T12:00:00Z",
        }),
      })
    );
    await authenticatedPage.route(`**/api/v1/jobs/${JOB_ID}/events**`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ job_id: JOB_ID, events: [LIVE_EVENT], count: 1 }),
      })
    );

    await authenticatedPage.goto(`/analysis/${JOB_ID}/process`);

    await expect(
      authenticatedPage.getByText(/1 evidence-backed claim from the static layer/)
    ).toBeVisible();
    await expect(
      authenticatedPage.getByText(/recorded no agent findings/)
    ).toHaveCount(0);
  });

  test("the stages filter hides the domain analysts", async ({ authenticatedPage }) => {
    await authenticatedPage.goto(`/analysis/${JOB_ID}/process`);
    await authenticatedPage.getByRole("button", { name: "Stages" }).click();
    await expect(authenticatedPage.getByText("Mediator", { exact: true })).toBeVisible();
    await expect(authenticatedPage.getByText("Static", { exact: true })).toHaveCount(0);
  });
});
