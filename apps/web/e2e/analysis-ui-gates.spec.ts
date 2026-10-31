import { test, expect } from "./fixtures";
import { MOCK_EVIDENCE_BUNDLE } from "./mocks";
import { COMPLETED_JOB, JOB_ID, MALWARE_REPORT, REPORT } from "./report-fixture";
import type { ReportDetailDTO } from "@/lib/api";

/**
 * What the UI gates found on the redesigned console (T-467): content that a
 * phone could not reach, a script tag React refused, ids printed bare, a
 * missing bundle logged twice, and the indicator order.
 */

const BASE = `/analysis/${JOB_ID}`;
const LONG = "C:\\Users\\Public\\Documents\\AppData\\Local\\Temp\\" + "x".repeat(120) + ".dll";

function gateReport(): ReportDetailDTO {
  return {
    ...REPORT,
    malware_report: {
      ...MALWARE_REPORT,
      technical_analysis: {
        execution_flow: [
          { order: 1, action: "Drops the loader and starts it [ev_0001, ev_0003].", voice: "observed", evidence_refs: [] },
        ],
        host_identifiers: [
          { kind: "Mutex", value: LONG, purpose: `Single instance guard, see ev_0002 ${LONG}`, evidence_refs: ["ev_0002"] },
        ],
        commands: [
          { id: "0x01", name: "download_and_execute_payload_from_remote", description: `Fetches ${LONG} [ev_0003]`, evidence_refs: ["ev_0003"] },
          { id: "0x02", name: "sleep", description: "Waits between beacons, ev_0002 shows the interval.", evidence_refs: [] },
        ],
        command_and_control: { title: "Command and control", body: `Beacons to ${LONG} [ev_0001]`, evidence_refs: [] },
      },
      sections: [
        ...(MALWARE_REPORT.sections ?? []),
        {
          key: "dynamic.wide_table",
          title: "Wide behaviour table",
          kind: "table",
          columns: ["ID", "Command", "Description", "Evidence"],
          rows: [
            ["1", "cmd /c " + "a".repeat(90), "A long description " + LONG, "ev_0001"],
            ["2", "powershell -enc " + "b".repeat(90), "Another one " + LONG, "ev_0002"],
          ],
          items: [],
          text: "",
          evidence_ids: ["ev_0001"],
          source: "tool:wide",
        },
        {
          key: "network.constant_evidence",
          title: "Network paths",
          kind: "table",
          columns: ["Kind", "Value", "Evidence", "Note"],
          rows: [
            ["path", "C:\\Windows\\System32", "ev_0006", "-"],
            ["path", "C:\\Users\\Public", "ev_0006", "-"],
            ["path", "C:\\Temp", "ev_0006", "-"],
          ],
          items: [],
          text: "",
          evidence_ids: [],
          source: "tool:paths",
        },
      ],
      consolidated_iocs: [
        { type: "URL", value: "http://a.test/withheld", kind: "url", source: "sandbox", published: "no: benign" },
        { type: "Domain", value: "z.test", kind: "domain", source: "sandbox", published: "yes" },
        { type: "Mutex", value: "Global\\M", kind: "mutex", source: "sandbox", published: "no: local" },
        { type: "SHA-256", value: "ab".repeat(32), kind: "hash", source: "identity", published: "yes" },
        { type: "Domain", value: "b.test", kind: "domain", source: "sandbox", published: "no: x" },
        ...Array.from({ length: 12 }, (_, i) => ({
          type: "File path",
          value: `C:\\f${i}`,
          kind: "path",
          source: "sandbox",
          published: "no: noise",
        })),
      ],
    },
  };
}

async function serve(page: import("@playwright/test").Page, report = gateReport()) {
  await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(report) }),
  );
  await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(COMPLETED_JOB) }),
  );
}

test.describe("at 390 px", () => {
  test.use({ viewport: { width: 390, height: 844 } });

  test("Behaviour clips nothing: wide tables scroll in named regions and long strings wrap", async ({
    sessionPage: page,
  }) => {
    await serve(page);
    await page.goto(`${BASE}/behaviour`);
    await expect(page.getByRole("heading", { name: "Technical analysis" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Wide behaviour table" })).toBeVisible();

    const tables = page.getByTestId("analysis-content").locator("table");
    expect(await tables.count()).toBeGreaterThanOrEqual(3);
    // Every table sits in a focusable, named region that scrolls sideways.
    const unwrapped = await page.evaluate(() =>
      [...document.querySelectorAll("#main-content table")]
        .filter((t) => {
          const box = t.parentElement!;
          return !(
            box.getAttribute("role") === "region" &&
            box.tabIndex === 0 &&
            (box.getAttribute("aria-label") ?? "").length > 0 &&
            getComputedStyle(box).overflowX === "auto"
          );
        })
        .map((t) => t.parentElement!.className.slice(0, 80) + " | " + (t.textContent ?? "").slice(0, 60)),
    );
    expect(unwrapped).toEqual([]);

    // Nothing is cut off: the page does not scroll sideways, and every cell and
    // prose element either ends inside the viewport or is inside a scroll region.
    const report = await page.evaluate(() => {
      const main = document.getElementById("main-content")!;
      const vw = document.documentElement.clientWidth;
      const clipped: string[] = [];
      for (const el of document.querySelectorAll<HTMLElement>("#main-content td, #main-content p, #main-content li, #main-content dd")) {
        let scroller: HTMLElement | null = el.parentElement;
        while (scroller && scroller !== main && getComputedStyle(scroller).overflowX !== "auto") scroller = scroller.parentElement;
        const inScroller = scroller && scroller !== main;
        if (!inScroller && el.getBoundingClientRect().right > vw + 1) clipped.push(el.textContent!.slice(0, 40));
        if (!inScroller && el.scrollWidth > el.clientWidth + 1 && getComputedStyle(el).display !== "table-cell")
          clipped.push(`scroll:${el.textContent!.slice(0, 40)}`);
      }
      return {
        doc: document.documentElement.scrollWidth - vw,
        main: main.scrollWidth - main.clientWidth,
        clipped,
      };
    });
    expect(report).toEqual({ doc: 0, main: 0, clipped: [] });
  });

  test("/evidence is not wider than the phone", async ({ sessionPage: page }) => {
    await serve(page);
    await page.route("**/api/v1/reports/*/evidence-bundle.json", (route) =>
      route.fulfill({ json: MOCK_EVIDENCE_BUNDLE }),
    );
    await page.goto(`${BASE}/evidence`);
    await expect(page.getByTestId("evidence-bundle")).toBeVisible();
    await page.waitForLoadState("networkidle");
    const wide = await page.evaluate(() => {
      const main = document.getElementById("main-content")!;
      return {
        doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        main: main.scrollWidth - main.clientWidth,
        mainBox: Math.round(main.getBoundingClientRect().right) - document.documentElement.clientWidth,
      };
    });
    expect(wide).toEqual({ doc: 0, main: 0, mainBox: 0 });
  });
});

test("Overview logs no console error", async ({ sessionPage: page }) => {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(err.message));
  await serve(page);
  await page.goto(BASE);
  await expect(page.getByRole("heading", { name: /Top findings/ })).toBeVisible();
  await page.waitForLoadState("networkidle");
  expect(errors).toEqual([]);
});

test("no console error when the analysis is reached by client-side navigation", async ({ authenticatedPage: page }) => {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") errors.push(msg.text());
  });
  await serve(page);
  await page.goto(BASE);
  await expect(page.getByRole("heading", { name: /Top findings/ })).toBeVisible();
  await page.getByRole("link", { name: "Dashboard" }).click();
  await expect(page).toHaveURL("/dashboard", { timeout: 30_000 });
  await page.goBack();
  await expect(page.getByRole("heading", { name: /Top findings/ })).toBeVisible();
  expect(errors.filter((e) => /script tag/i.test(e))).toEqual([]);
});

test("Behaviour shows evidence ids as marks that open the drawer, never as text", async ({ sessionPage: page }) => {
  await serve(page);
  await page.goto(`${BASE}/behaviour`);
  const panel = page.getByRole("heading", { name: "Technical analysis" }).locator("xpath=ancestor::div[contains(@class,'bg-bg-surface')][1]");
  await expect(panel).toBeVisible();
  await expect(panel).not.toContainText(/ev_\d+/);
  await expect(panel.locator("[data-citation]").first()).toBeVisible();
  const flow = panel.getByRole("listitem").first();
  await flow.locator("[data-citation]").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
});

test("every scroll region on a tab has its own name, and a cited id stays in the mark's name", async ({
  sessionPage: page,
}) => {
  await serve(page);
  for (const tab of ["", "/behaviour", "/network", "/static", "/indicators", "/evidence/conversation"]) {
    await page.goto(`${BASE}${tab}`);
    await page.waitForLoadState("networkidle");
    const names = await page.evaluate(() =>
      [...document.querySelectorAll('[role="region"][aria-label$="scrolls sideways"]')].map((e) => e.getAttribute("aria-label")),
    );
    expect(new Set(names).size, `${tab}: ${names.join(" | ")}`).toBe(names.length);
  }
  await page.goto(`${BASE}/behaviour`);
  await expect(page.getByRole("button", { name: /Evidence for this statement, 1 record \(ev_0002\)/ }).first()).toBeVisible();
});

test("Network shows the constant Evidence column as a mark, not as ev_0006", async ({ sessionPage: page }) => {
  await serve(page);
  await page.goto(`${BASE}/network`);
  const section = page.getByRole("heading", { name: "Network paths" }).locator("xpath=ancestor::div[contains(@class,'bg-bg-surface')][1]");
  await expect(section).toBeVisible();
  await expect(section).toContainText("the same on every row below");
  await expect(section).not.toContainText(/ev_0006/);
  await section.locator("[data-citation]").first().click();
  await expect(page.getByRole("dialog")).toBeVisible();
});

test("Indicators list the published rows first", async ({ sessionPage: page }) => {
  await serve(page);
  await page.goto(`${BASE}/indicators`);
  const panel = page.getByTestId("indicators-panel");
  const first = panel.locator("tbody tr");
  await expect(first.first()).toBeVisible();
  const texts = await first.allInnerTexts();
  expect(texts[0]).toContain("published");
  expect(texts[1]).toContain("published");
  expect(texts[2]).not.toContain("withheld,published");
  expect(texts.slice(0, 2).join(" ")).toContain("z.test");
});

test("a server without the evidence bundle says so, asks once, and keeps Records one link away", async ({
  sessionPage: page,
}) => {
  await serve(page);
  let asks = 0;
  await page.route("**/api/v1/reports/*/evidence-bundle.json", (route) => {
    asks += 1;
    return route.fulfill({ status: 404, json: { detail: "Not Found" } });
  });
  await page.goto(`${BASE}/evidence`);
  const absent = page.getByTestId("evidence-bundle-absent");
  await expect(absent).toContainText("The evidence bundle is not available from this server");
  await page.waitForLoadState("networkidle");
  expect(asks).toBe(1);
  await absent.getByRole("link", { name: "Records" }).click();
  await expect(page).toHaveURL(`${BASE}/evidence/records`);
});

test("the dashboard chart is one named image, not a focusable presentation node", async ({ authenticatedPage: page }) => {
  await page.goto("/dashboard");
  await expect(page.getByRole("img", { name: /^Verdict mix:/ })).toBeVisible();
  const conflict = await page.evaluate(
    () =>
      [...document.querySelectorAll("svg.recharts-surface")].filter(
        (s) => s.getAttribute("role") === "presentation" && s.hasAttribute("tabindex"),
      ).length,
  );
  expect(conflict).toBe(0);
});
