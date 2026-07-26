import { test, expect } from "./fixtures";

/**
 * The agent transcript — the same panel live and after the fact.
 *
 * These drive the post-run path, because it is the one that can silently rot:
 * it reconstructs the conversation from `agent_findings` and `negotiation_log`
 * rather than replaying events, so a schema change breaks it without breaking
 * the live feed. The route is mocked so the assertions do not depend on
 * whatever happens to be in the dev database.
 */

const JOB_ID = "11111111-2222-3333-4444-555555555555";

const REPORT = {
  id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  job_id: JOB_ID,
  // Raw backend spelling on purpose: the transcript must normalise it.
  verdict: "Malware",
  overall_confidence: 0.6,
  agent_findings: [
    {
      agent_name: "static",
      domain: "static",
      claims: [
        {
          claim: "Imports VirtualAllocEx and WriteProcessMemory",
          evidence_ref: "IAT: KERNEL32.dll!VirtualAllocEx",
          confidence: 0.9,
          technique_id: "T1055",
        },
      ],
      dissent_items: [],
      revision_rounds: 0,
      final_confidence: 0.9,
      status: "complete",
      status_reason: null,
    },
    {
      agent_name: "dynamic",
      domain: "dynamic",
      claims: [],
      dissent_items: [],
      revision_rounds: 0,
      final_confidence: 0,
      status: "failed",
      status_reason: "sandbox unreachable",
    },
  ],
  negotiation_log: {
    discussion_history: [
      {
        round: 1,
        agent: "Mediator",
        argument: "Static evidence is uncorroborated by the dynamic layer.",
        confidence: 55,
      },
    ],
    is_consensus: false,
    iteration_count: 1,
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
        body: JSON.stringify({
          id: JOB_ID,
          status: "completed",
          sample_filename: "evil.exe",
          verdict: "Malware",
        }),
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
    await expect(
      authenticatedPage.getByText(/Imports VirtualAllocEx and WriteProcessMemory/)
    ).toBeVisible();
    await expect(
      authenticatedPage.getByText(/KERNEL32\.dll!VirtualAllocEx/)
    ).toBeVisible();
    await expect(authenticatedPage.getByText("T1055", { exact: true })).toBeVisible();
  });

  test("the stages filter hides the domain analysts", async ({ authenticatedPage }) => {
    await authenticatedPage.goto(`/analysis/${JOB_ID}/process`);
    await authenticatedPage.getByRole("button", { name: "Stages" }).click();
    await expect(authenticatedPage.getByText("Mediator", { exact: true })).toBeVisible();
    await expect(authenticatedPage.getByText("Static", { exact: true })).toHaveCount(0);
  });
});
