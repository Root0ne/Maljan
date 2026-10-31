import { test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT } from "./report-fixture";
import type { FollowUp } from "@/types/malware-report";

/**
 * Chat: questions about a finished analysis in a drawer that slides in from
 * the right. Pinned here: the whole earlier conversation with each answer
 * drawn as Markdown and its citations as evidence marks, the open questions
 * the analysis left offered as suggestions, Enter sends and Shift+Enter does
 * not, a refused question says so and can be asked again, Escape closes and
 * gives focus back, Tab stays inside while the drawer covers the page, and
 * the drawer stays open from tab to tab while it sits beside the page.
 */

const BASE = `/analysis/${JOB_ID}`;

function followUp(over: Partial<FollowUp> = {}): FollowUp {
  return {
    id: "f1",
    job_id: JOB_ID,
    report_id: REPORT.id,
    question: "Which address does it beacon to?",
    outcome: "established",
    answer: {
      question: "Which address does it beacon to?",
      outcome: "established",
      answer: "It beacons to **cdn.example-update.net** over HTTPS [ev_0001].\n\n- first contact after 30 s\n- then every 5 min",
      evidence_ids: ["ev_0001"],
      looked_at: [],
      open_questions: ["Which mutex does it create?"],
      checks: [],
    },
    model: "test-model",
    model_source: "the run's settings",
    report_sha256: "a".repeat(64),
    record: { digest: "d" },
    notes: [],
    answered_at: "2026-10-23T10:00:00Z",
    ...over,
  };
}

async function serve(page: import("@playwright/test").Page, held: FollowUp[]) {
  await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) => route.fulfill({ json: REPORT }));
  await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) => route.fulfill({ json: COMPLETED_JOB }));
  await page.route(`**/api/v1/jobs/${JOB_ID}/follow-ups`, async (route) => {
    if (route.request().method() === "POST") {
      const { question } = route.request().postDataJSON() as { question: string };
      if (question.includes("refuse")) {
        await route.fulfill({ status: 503, json: { detail: "the model is not reachable" } });
        return;
      }
      await route.fulfill({
        json: followUp({
          id: `f${held.length + 2}`,
          question,
          answer: { ...followUp().answer, question, answer: "The mutex is `Global\\UpdateSvcMtx`.", open_questions: [] },
        }),
      });
      return;
    }
    await route.fulfill({ json: { job_id: JOB_ID, follow_ups: held } });
  });
}

test.describe("Chat", () => {
  test("opens from the header with the whole conversation, and Escape gives focus back", async ({ sessionPage: page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await serve(page, [followUp()]);
    await page.goto(BASE);
    const open = page.getByRole("region", { name: "Analysis summary" }).getByRole("button", { name: "Chat" });
    await open.click();
    const drawer = page.getByRole("dialog", { name: "Chat about this analysis" });
    await expect(drawer).toBeVisible();
    await expect(open).toHaveAttribute("aria-expanded", "true");
    await expect(drawer.getByRole("textbox", { name: "Your question about this analysis" })).toBeFocused();
    // 420 px wide, the full height under the app header, at the right edge.
    const box = (await drawer.boundingBox())!;
    expect(Math.round(box.width)).toBe(420);
    expect(Math.round(box.y)).toBe(48);
    expect(Math.round(box.x + box.width)).toBe(1440);

    const log = drawer.getByRole("log", { name: "Questions and answers" });
    await expect(log).toContainText("Which address does it beacon to?");
    // The answer is Markdown: bold and a list, never the raw marks.
    await expect(log.locator("strong", { hasText: "cdn.example-update.net" })).toBeVisible();
    await expect(log.locator("ul > li", { hasText: "first contact after 30 s" })).toBeVisible();
    await expect(log).not.toContainText("**");
    await expect(log).not.toContainText("ev_0001]");
    await expect(log.getByRole("button", { name: "Evidence for this statement, 1 record" })).toBeVisible();
    // What the analysis left open is offered as the next question.
    await expect(drawer.getByRole("button", { name: "Which mutex does it create?" })).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();
    await expect(open).toBeFocused();
  });

  test("Enter sends, Shift+Enter adds a line, and the answer joins the thread and the page", async ({ sessionPage: page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await serve(page, []);
    await page.goto(BASE);
    await page.getByRole("region", { name: "Analysis summary" }).getByRole("button", { name: "Chat" }).click();
    const drawer = page.getByRole("dialog", { name: "Chat about this analysis" });
    const field = drawer.getByRole("textbox", { name: "Your question about this analysis" });
    await expect(drawer.getByText("No follow-up question has been asked.")).toHaveCount(0);
    await field.fill("Which mutex");
    await field.press("Shift+Enter");
    await field.pressSequentially("does it create?");
    await expect(field).toHaveValue("Which mutex\ndoes it create?");
    await field.press("Enter");
    const log = drawer.getByRole("log");
    // Sent on one line, answered, and drawn as Markdown.
    await expect(log).toContainText("Which mutex does it create?");
    await expect(log.locator("code", { hasText: "Global\\UpdateSvcMtx" })).toBeVisible();
    await expect(field).toHaveValue("");
    // The rest of the page hears of it.
    await expect(page.getByRole("region", { name: "Follow-up questions" })).toContainText("1 question asked");
  });

  test("a refused question says why and can be asked again", async ({ sessionPage: page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await serve(page, []);
    await page.goto(BASE);
    await page.getByRole("region", { name: "Analysis summary" }).getByRole("button", { name: "Chat" }).click();
    const drawer = page.getByRole("dialog", { name: "Chat about this analysis" });
    await drawer.getByRole("textbox").fill("Please refuse this");
    await drawer.getByRole("button", { name: "Ask", exact: true }).click();
    const alert = drawer.getByRole("alert");
    await expect(alert).toContainText("The question was not answered");
    await expect(alert.getByRole("button", { name: "Ask again" })).toBeVisible();
    await expect(drawer.getByRole("textbox")).toHaveValue("Please refuse this");
  });

  test("beside the page it stays open from tab to tab", async ({ sessionPage: page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await serve(page, [followUp()]);
    await page.goto(BASE);
    await page.getByRole("region", { name: "Analysis summary" }).getByRole("button", { name: "Chat" }).click();
    const drawer = page.getByRole("dialog", { name: "Chat about this analysis" });
    await expect(drawer).not.toHaveAttribute("aria-modal", "true");
    // The page makes room: nothing sits under the drawer.
    const content = (await page.getByTestId("analysis-content").boundingBox())!;
    expect(content.x + content.width).toBeLessThanOrEqual(1440 - 420 + 1);
    await page.getByRole("navigation", { name: "Analysis sections" }).getByRole("link", { name: /^Network/ }).click();
    await expect(page).toHaveURL(`${BASE}/network`);
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole("log")).toContainText("Which address does it beacon to?");
  });

  test("over the page on a phone it is modal: Tab stays inside, and the page behind is inert", async ({ sessionPage: page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await serve(page, [followUp()]);
    await page.goto(BASE);
    await page.getByRole("region", { name: "Analysis summary" }).getByRole("button", { name: "Chat" }).click();
    const drawer = page.getByRole("dialog", { name: "Chat about this analysis" });
    await expect(drawer).toHaveAttribute("aria-modal", "true");
    await expect(drawer.getByRole("textbox")).toBeFocused();
    for (let i = 0; i < 12; i++) {
      await page.keyboard.press("Tab");
      expect(await drawer.evaluate((el) => el.contains(document.activeElement))).toBe(true);
    }
    expect(await page.getByTestId("analysis-content").evaluate((el) => Boolean(el.closest("[inert]")))).toBe(true);
    await drawer.getByRole("button", { name: "Close chat" }).click();
    await expect(drawer).toBeHidden();
    expect(await page.getByTestId("analysis-content").evaluate((el) => Boolean(el.closest("[inert]")))).toBe(false);
  });

  test("is not offered while the job runs", async ({ sessionPage: page }) => {
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) => route.fulfill({ json: { ...COMPLETED_JOB, status: "running" } }));
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) => route.fulfill({ status: 404, json: { detail: "no report" } }));
    await page.goto(BASE);
    await expect(page.getByRole("region", { name: "Analysis summary" })).toContainText("Analysis running");
    await expect(page.getByRole("button", { name: "Chat" })).toHaveCount(0);
  });
});
