import { alerts, test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, REPORT } from "./report-fixture";
import RUN from "./conversation-run.json";
import EVIDENCE from "./conversation-evidence.json";

/**
 * The Conversation tab as a group chat, against a real run's feed.
 *
 * `conversation-run.json` is the event feed of a stored nine-agent run (the
 * pack, six analysts, four debate rounds with the mediator, the judge),
 * redacted: hosts, addresses, hashes and paths replaced, tool and model names
 * made generic, long texts cut. `conversation-evidence.json` is the same run's
 * evidence ledger, redacted the same way, which is where a tool call opened in
 * the conversation reads its full result from.
 */

type FeedEvent = { type: string; data: Record<string, unknown>; ts: string };
type Entry = { entry_id: string };

const FEED = RUN as FeedEvent[];
const LEDGER = EVIDENCE as Entry[];

async function mockRun(
  page: import("@playwright/test").Page,
  options: { events?: FeedEvent[]; status?: string; evidence?: "ok" | "fail"; ledger?: Entry[] } = {},
) {
  const events = options.events ?? FEED;
  await page.route(`**/api/v1/jobs/${JOB_ID}/events**`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ job_id: JOB_ID, events, count: events.length }),
    }),
  );
  await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({ ...COMPLETED_JOB, status: options.status ?? COMPLETED_JOB.status }),
    }),
  );
  await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
    options.status === "running"
      ? route.fulfill({ status: 404, body: JSON.stringify({ detail: "Not found" }) })
      : route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(REPORT) }),
  );
  await page.route(`**/api/v1/jobs/${JOB_ID}/evidence?**`, (route) => {
    if (options.evidence === "fail") {
      return route.fulfill({ status: 500, body: JSON.stringify({ detail: "ledger offline" }) });
    }
    const url = new URL(route.request().url());
    const pageNo = Number(url.searchParams.get("page") ?? 1);
    const size = Number(url.searchParams.get("page_size") ?? 50);
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        job_id: JOB_ID,
        entries: (options.ledger ?? LEDGER).slice((pageNo - 1) * size, pageNo * size),
        total: LEDGER.length,
        page: pageNo,
        page_size: size,
      }),
    });
  });
}

const stream = (page: import("@playwright/test").Page) => page.getByTestId("conversation-stream");
const URL_PATH = `/analysis/${JOB_ID}/evidence/conversation`;

test.describe("Conversation as a group chat", () => {
  test("groups each agent's messages under its name, and folds its calls into a strip", async ({
    sessionPage: page,
  }) => {
    await mockRun(page);
    await page.goto(URL_PATH);
    const feed = stream(page);

    // Each message is an article labelled with who said it.
    await expect(feed.getByRole("article", { name: /^Dynamic analyst/ }).first()).toBeVisible();
    // The reverser's calls are one strip, not a row each.
    const strip = feed.getByRole("button", { name: /\d+ tools/ }).first();
    await expect(strip).toHaveAttribute("aria-expanded", "false");
    // No call is drawn until a strip is opened.
    await expect(feed.getByRole("link", { name: "ev_0086" })).toHaveCount(0);
    await expect(alerts(page)).toHaveCount(0);
  });

  test("draws the mediator apart, and an answer quotes it and leads back to it", async ({
    sessionPage: page,
  }) => {
    await mockRun(page);
    await page.goto(URL_PATH);
    const feed = stream(page);

    const mediator = feed.getByRole("article", { name: /^Mediator/ }).first();
    await expect(mediator).toBeVisible();
    // The name it introduced itself with heads the group, not the bubble.
    await expect(mediator).not.toContainText("Mediator: The analysts agree");
    await expect(mediator).toContainText("The analysts agree on the core facts");

    const quote = feed.getByRole("button", { name: /^Replying to Mediator/ }).first();
    await expect(quote).toBeVisible();
    await quote.click();
    await expect(mediator).toBeFocused();
  });

  test("a quote whose question a filter hid clears the filter and leads to it", async ({
    sessionPage: page,
  }) => {
    await mockRun(page);
    await page.goto(URL_PATH);
    const feed = stream(page);

    // Narrowed to one analyst, the mediator it answers is not drawn.
    await page.getByRole("button", { name: /^Dynamic analyst/ }).click();
    await expect(feed.getByRole("article", { name: /^Mediator/ })).toHaveCount(0);

    await feed.getByRole("button", { name: /^Replying to Mediator/ }).first().click();
    await expect(page.getByRole("button", { name: "Clear filters" })).toHaveCount(0);
    await expect(feed.getByRole("article", { name: /^Mediator/ }).first()).toBeFocused();
  });

  test("a large record with spilled parts opens with what was cut said", async ({ sessionPage: page }) => {
    const big = "rx_bytes 108299 tx_bytes 2521\n".repeat(400);
    const ledger = LEDGER.map((entry) =>
      entry.entry_id === "ev_0086"
        ? {
            ...entry,
            output: big,
            structured: null,
            truncated: true,
            chars_dropped: 48_000,
            spilled: [{ part: "output", key: "jobs/x/ev_0086/output", bytes: 60_000 }],
          }
        : entry,
    );
    await mockRun(page, { ledger });
    await page.goto(URL_PATH);
    const feed = stream(page);

    await page.getByRole("button", { name: "Tool calls" }).click();
    const row = feed.locator("li").filter({ has: page.getByRole("link", { name: "ev_0086" }) });
    await row.getByRole("button", { name: /sandbox_network$/ }).click();
    await expect(row).toContainText("The tool-output guardrail cut 48,000 characters");
    await expect(row).toContainText("The full output (60,000 bytes) is kept whole in object storage.");
    // Long text opens a page at a time.
    const more = row.getByRole("button", { name: /^Show more \(\d+ more characters\)$/ });
    await expect(more).toBeVisible();
    await more.click();
    await expect(row.getByRole("button", { name: "Show less" })).toBeVisible();
  });

  test("opens a call to its full result, read from the evidence", async ({ sessionPage: page }) => {
    await mockRun(page);
    await page.goto(URL_PATH);
    const feed = stream(page);

    await page.getByRole("button", { name: "Tool calls" }).click();
    // The dynamic analyst's call, filed in the ledger as ev_0086.
    const row = feed.locator("li").filter({ has: page.getByRole("link", { name: "ev_0086" }) });
    const call = row.getByRole("button", { name: /sandbox_network$/ });
    await call.scrollIntoViewIfNeeded();
    await call.click();
    await expect(call).toHaveAttribute("aria-expanded", "true");
    // The preview the event carried stops long before this sentence.
    await expect(row).toContainText("The report does not hold this part");
    await expect(row).toContainText("Arguments");
  });

  test("falls back to the preview, and says so, when the evidence cannot be read", async ({
    sessionPage: page,
  }) => {
    await mockRun(page, { evidence: "fail" });
    await page.goto(URL_PATH);
    const feed = stream(page);

    await page.getByRole("button", { name: "Tool calls" }).click();
    const row = feed.locator("li").filter({ has: page.getByRole("link", { name: "ev_0086" }) });
    const call = row.getByRole("button", { name: /sandbox_network$/ });
    await call.scrollIntoViewIfNeeded();
    await call.click();
    await expect(row).toContainText("This is the preview the event carried");
    await expect(row).not.toContainText("The report does not hold this part");
  });

  test("narrows to the failures", async ({ sessionPage: page }) => {
    await mockRun(page);
    await page.goto(URL_PATH);
    const feed = stream(page);

    await page.getByRole("button", { name: "Failures" }).click();
    await expect(feed.getByRole("button", { name: /2 tools.* 2 failed/ })).toBeVisible();
    await expect(feed.getByRole("link", { name: "ev_0041" })).toBeVisible();
    await expect(feed.getByRole("article", { name: /^Mediator/ })).toHaveCount(0);
  });

  test("a live run says who is writing, and offers a way back to new messages", async ({
    sessionPage: page,
  }) => {
    let push: ((frame: FeedEvent) => void) | null = null;
    await page.routeWebSocket("**/ws/analysis/**", (ws) => {
      push = (frame) => ws.send(JSON.stringify(frame));
    });
    const cut = FEED.filter((e) => Number(e.data.seq) <= 568);
    await mockRun(page, { events: cut, status: "running" });
    await page.goto(URL_PATH);

    await expect(stream(page)).toContainText(/Static analyst \(scanner\)[^…]* writing…/);

    await page.evaluate(() => document.getElementById("main-content")?.scrollTo({ top: 0 }));
    const back = page.getByRole("button", { name: /Jump to latest|New messages/ });
    await expect(back).toBeVisible();
    await expect.poll(() => push !== null).toBe(true);
    push!({
      type: "agent_message",
      ts: "2026-10-27T04:06:40Z",
      data: {
        seq: 569,
        kind: "says",
        role: "reviser",
        round: 3,
        stage: "debate",
        status: "complete",
        speaker: "network",
        display_name: "Network analyst",
        text: "The two base URLs are the only hosts the sample is coded to call.",
      },
    });
    await expect(page.getByRole("button", { name: "New messages" })).toBeVisible();
    await page.getByRole("button", { name: "New messages" }).click();
    await expect(stream(page)).toContainText("The two base URLs are the only hosts");
  });
});
