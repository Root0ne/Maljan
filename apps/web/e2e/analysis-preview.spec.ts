import { alerts, test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, MALWARE_REPORT, REPORT } from "./report-fixture";
import type { ReportDetailDTO } from "@/lib/api";

/**
 * The new analysis page, behind NEXT_PUBLIC_UI_NEXT (set for the suite in
 * playwright.config.ts).
 *
 * It lives at /preview/analysis/{id} beside today's pages, which the other
 * analysis specs keep covering unchanged. What is pinned here is what the
 * new layout promises a reader: the verdict, score and file in the first
 * glance; six tabs, each its own URL; the evidence behind a finding one
 * click away in a side panel that gives focus back; one Export menu grouped
 * by intent; remarks only when the run is not whole; no internal words; and
 * a page that fits a phone without sideways scrolling.
 */

const BASE = `/preview/analysis/${JOB_ID}`;

/** The fixture report with the parts the Overview draws and the fixture lacks. */
function previewReport(over: Partial<ReportDetailDTO> = {}): ReportDetailDTO {
  return {
    ...REPORT,
    malware_report: {
      ...MALWARE_REPORT,
      key_findings: [
        { text: "Allocates and writes executable memory into an unrelated process.", evidence_ids: ["ev_0001"] },
        ...(MALWARE_REPORT.key_findings ?? []).slice(1),
      ],
      // The report's prose can still cite its records inline; the page must not print them.
      executive_summary:
        "The sample injects into a running process [ev_0001, ev_0003, …] and beacons to a newly registered domain over HTTPS.",
      // A dynamic layer contributed, but the report's basis is code only:
      // the page must say so, not "observed".
      ttp_mappings: MALWARE_REPORT.ttp_mappings.map((t) => ({
        ...t,
        evidence_roots: ["ev_0002"],
        contributing_layers: ["static", "dynamic"],
        source_kinds: { code: 2 },
      })),
      technical_analysis: {
        configuration: [
          { key: "C2 host", value: "cdn.example-update.net", how_obtained: "decrypted", evidence_refs: [] },
          { key: "Mutex", value: "Global\\UpdateSvcMtx", how_obtained: "observed", evidence_refs: [] },
        ],
      },
      run_summary: {
        ...MALWARE_REPORT.run_summary,
        sandbox_signature_scale: {
          name: "test scale",
          max: 10,
          rungs: ["Informational", "Informational", "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"],
        },
      },
    },
    ...over,
  };
}

async function serve(page: import("@playwright/test").Page, report: ReportDetailDTO) {
  await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(report) }),
  );
  await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(COMPLETED_JOB) }),
  );
}

test.describe("Analysis preview", () => {
  test("the header and Overview say what the sample is and what was found", async ({ sessionPage: page }) => {
    const pageErrors: string[] = [];
    page.on("pageerror", (err) => pageErrors.push(err.message));
    await serve(page, previewReport());
    await page.goto(BASE);

    const header = page.getByRole("region", { name: "Analysis summary" });
    await expect(header.getByRole("heading", { level: 1, name: "invoice_scan.exe" })).toBeVisible();
    await expect(header.getByText("Malicious", { exact: true })).toBeVisible();
    // The ring is the verdict's confidence, never a derived score.
    const ring = header.getByRole("img", { name: "Malicious, confidence 91 percent" });
    await expect(ring).toBeVisible();
    await expect(ring).toContainText("91%");
    await expect(ring).toContainText("Confidence");
    await expect(header.getByTestId("confidence-why")).toHaveText("How sure the analysis is of this verdict");
    await expect(header.getByText("AgentTesla")).toBeVisible();
    await expect(header.getByRole("button", { name: /^Copy SHA-256 of invoice_scan\.exe$/ })).toBeVisible();
    await header.getByRole("button", { name: "All hashes" }).click();
    await expect(header.getByText("5d41402abc4b2a76b9719d911017c592")).toBeVisible();

    const nav = page.getByRole("navigation", { name: "Analysis sections" });
    await expect(nav.getByRole("link")).toHaveText([
      "Overview",
      /^Behaviour/,
      /^Network/,
      /^Static & code/,
      /^Indicators & detection/,
      /^Evidence/,
    ]);
    await expect(nav.getByRole("link", { name: "Overview" })).toHaveAttribute("aria-current", "page");

    await expect(page.getByRole("heading", { name: /Top findings/ })).toBeVisible();
    const table = page.getByRole("table");
    await expect(table.getByRole("row").nth(1)).toContainText("High 4/5");
    await expect(table.getByRole("row").nth(2)).toContainText("Unrated");
    await expect(table.getByRole("row").nth(2)).toContainText("Read from the code, not observed running");
    await expect(table.getByRole("row").nth(2)).not.toContainText("Observed when the sample ran");
    await expect(page.getByText("Files written").locator("..")).toContainText("Not found");
    await expect(page.getByText("cdn.example-update.net").first()).toBeVisible();
    await expect(page.getByText("Hunt for WriteProcessMemory into non-child processes.")).toBeVisible();

    // A complete run draws no remarks, and nothing failed.
    await expect(page.getByRole("region", { name: "Remarks" })).toHaveCount(0);
    await expect(alerts(page)).toHaveCount(0);
    expect(pageErrors).toEqual([]);

    // At most one primary action, and none of the pipeline's own words.
    await expect(page.locator('[data-variant="primary"]:visible')).toHaveCount(0);
    const text = await page.getByTestId("analysis-preview").innerText();
    expect(text).not.toMatch(/\b(ledger|judge|producer|nudge)\b/i);
    expect(text).not.toMatch(/\bev_\d+/);
  });

  test("a finding's caret opens its evidence in the side panel and gives focus back", async ({
    sessionPage: page,
  }) => {
    await serve(page, previewReport());
    await page.goto(BASE);

    const caret = page.getByRole("button", { name: "Show evidence: Process Injection" });
    await caret.click();
    const drawer = page.getByRole("dialog", { name: "Process Injection" });
    await expect(drawer).toBeVisible();
    await expect(drawer).toContainText("Read from the code, not observed running.");
    await expect(drawer).toContainText("WriteProcessMemory into pid 640");
    await expect(drawer.getByRole("link", { name: /Record 1/ })).toHaveAttribute(
      "href",
      `/analysis/${JOB_ID}/evidence?evidence=ev_0002`,
    );
    await expect(drawer.getByRole("button", { name: "Close details" })).toBeFocused();

    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0);
    await expect(caret).toBeFocused();
  });

  test("a key finding's superscript opens the records behind it", async ({ sessionPage: page }) => {
    await serve(page, previewReport());
    await page.goto(BASE);
    await page.getByRole("button", { name: "Evidence for key finding 1" }).click();
    const drawer = page.getByRole("dialog");
    await expect(drawer.getByRole("link", { name: /Record 1/ })).toHaveAttribute(
      "href",
      `/analysis/${JOB_ID}/evidence?evidence=ev_0001`,
    );
    await drawer.getByRole("button", { name: "Close details" }).click();
    await expect(drawer).toHaveCount(0);
  });

  test("ids cited in the summary prose become one evidence link, never printed", async ({ sessionPage: page }) => {
    await serve(page, previewReport());
    await page.goto(BASE);
    const summary = page.getByRole("region", { name: "Summary", exact: true });
    await expect(summary).toContainText("injects into a running process and beacons");
    await expect(summary).not.toContainText("ev_");
    await summary.getByRole("button", { name: "Evidence for this statement, 2 records" }).click();
    const drawer = page.getByRole("dialog", { name: "Evidence for this statement" });
    await expect(drawer.getByRole("link", { name: /Record 1/ })).toHaveAttribute(
      "href",
      `/analysis/${JOB_ID}/evidence?evidence=ev_0001`,
    );
    await expect(drawer.getByRole("link", { name: /Record 2/ })).toHaveAttribute(
      "href",
      `/analysis/${JOB_ID}/evidence?evidence=ev_0003`,
    );
  });

  test("while loading, the header claims nothing", async ({ sessionPage: page }) => {
    let release: () => void = () => {};
    const held = new Promise<void>((resolve) => (release = resolve));
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(previewReport()) }),
    );
    await page.route(`**/api/v1/jobs/${JOB_ID}`, async (route) => {
      await held;
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(COMPLETED_JOB) });
    });
    await page.goto(BASE);
    const header = page.getByRole("region", { name: "Analysis summary" });
    await expect(header).toHaveAttribute("aria-busy", "true");
    await expect(header).toContainText("Loading the analysis…");
    await expect(header).not.toContainText(/No verdict|No report|Unnamed sample|Family not identified/);
    await expect(page.getByRole("navigation", { name: "Analysis sections" })).toHaveCount(0);
    release();
    await expect(header.getByRole("heading", { level: 1, name: "invoice_scan.exe" })).toBeVisible();
    await expect(header).not.toHaveAttribute("aria-busy", "true");
  });

  test("on a phone the header folds to one short row once the page scrolls", async ({ sessionPage: page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await serve(page, previewReport());
    await page.goto(BASE);
    const header = page.getByRole("region", { name: "Analysis summary" });
    await expect(page.getByRole("heading", { name: /Top findings/ })).toBeVisible();
    await page.evaluate(() => document.getElementById("main-content")!.scrollTo(0, 400));
    await expect(header).toHaveAttribute("data-folded", "true");
    const box = await header.boundingBox();
    expect(box!.height).toBeLessThanOrEqual(72);
    // Verdict, confidence, Export and Ask stay; chips, hashes and the why-line go.
    await expect(header.getByText("Malicious", { exact: true })).toBeVisible();
    await expect(header.getByRole("img", { name: "Malicious, confidence 91 percent" })).toBeVisible();
    await expect(header.getByRole("button", { name: "Export" })).toBeVisible();
    await expect(header.getByRole("button", { name: "Ask" })).toBeVisible();
    await expect(header.getByText("trojan")).toHaveCount(0);
    await expect(header.getByRole("button", { name: "All hashes" })).toHaveCount(0);
    await expect(header.getByTestId("confidence-why")).toHaveCount(0);
    // Back at the top it opens again.
    await page.evaluate(() => document.getElementById("main-content")!.scrollTo(0, 0));
    await expect(header.getByTestId("confidence-why")).toBeVisible();
  });

  test("one Export menu, grouped Quick, Deep and Data, saves through the existing downloads", async ({
    sessionPage: page,
  }) => {
    await serve(page, previewReport());
    await page.goto(BASE);

    const button = page.getByRole("button", { name: "Export" });
    await expect(button).toHaveAttribute("aria-haspopup", "menu");
    await button.click();
    const menu = page.getByRole("menu", { name: "Export" });
    await expect(menu.getByRole("group")).toHaveCount(3);
    for (const name of ["Quick", "Deep", "Data"]) await expect(menu.getByRole("group", { name })).toBeVisible();
    await expect(menu.getByRole("menuitem", { name: /MISP attributes/ })).toBeDisabled();
    await expect(menu.getByRole("menuitem", { name: /MISP attributes/ })).toContainText(
      "None were generated for this analysis",
    );
    // The first usable item has focus, and Escape gives it back to the button.
    await expect(menu.getByRole("menuitem").first()).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(menu).toHaveCount(0);
    await expect(button).toBeFocused();

    await button.click();
    const download = page.waitForEvent("download");
    await page.getByRole("menuitem", { name: /Indicator list/ }).click();
    expect((await download).suggestedFilename()).toMatch(/^maljan-[0-9a-f]{8}-iocs\.json$/);
  });

  test("each tab is its own URL; the ones still to build say what they will hold", async ({
    sessionPage: page,
  }) => {
    await serve(page, previewReport());
    await page.goto(BASE);
    const nav = page.getByRole("navigation", { name: "Analysis sections" });
    await nav.getByRole("link", { name: /^Network/ }).click();
    await expect(page).toHaveURL(`${BASE}/network`);
    await expect(nav.getByRole("link", { name: /^Network/ })).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { name: "Network: coming next" })).toBeVisible();
    await expect(page.getByText("Hosts on the left, their requests on the right")).toBeVisible();
    await expect(page.getByRole("link", { name: "Network", exact: true }).last()).toHaveAttribute(
      "href",
      `/analysis/${JOB_ID}/network`,
    );

    await page.goto(`${BASE}/evidence`);
    await expect(page.getByRole("heading", { name: "Evidence: coming next" })).toBeVisible();
  });

  test("remarks appear, in plain words, only when the run is not whole", async ({ sessionPage: page }) => {
    const report = previewReport({ incomplete_reason: "the report could not be finished" });
    report.malware_report = {
      ...report.malware_report!,
      run_summary: { ...report.malware_report!.run_summary, failed_analysts: ["dynamic"] },
    };
    await serve(page, report);
    await page.goto(BASE);
    const remarks = page.getByRole("region", { name: "Remarks" });
    await expect(remarks.getByRole("listitem")).toHaveText([
      "The analysis did not finish; some sections may be missing.",
      "A stage of the analysis failed; its findings are missing from this report.",
    ]);
    // The stored reason is only the tooltip, never the sentence.
    await expect(remarks).not.toContainText("dynamic");
    await expect(remarks.getByRole("listitem").first()).toHaveAttribute("title", "the report could not be finished");
  });

  test("the theme switch puts the page on light tokens and back", async ({ sessionPage: page }) => {
    await serve(page, previewReport());
    await page.emulateMedia({ colorScheme: "dark" });
    await page.goto(BASE);
    await expect(page.locator("html")).toHaveAttribute("data-ui-theme", "dark");
    await page.getByRole("button", { name: "Switch to light theme" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-ui-theme", "light");
    const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
    expect(bg).toBe("rgb(246, 248, 250)");
    await page.getByRole("button", { name: "Switch to dark theme" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-ui-theme", "dark");
  });

  test("the light theme is on before the first paint of a full load", async ({ sessionPage: page }) => {
    await serve(page, previewReport());
    await page.emulateMedia({ colorScheme: "light" });
    // Read the attribute as the document is parsed, before any React effect.
    await page.addInitScript(() => {
      document.addEventListener("DOMContentLoaded", () => {
        (window as unknown as { __themeAtParse: string | null }).__themeAtParse =
          document.documentElement.getAttribute("data-ui-theme");
      });
    });
    const response = await page.goto(BASE);
    // The server's own HTML carries the boot script, so no React effect is
    // needed for the first paint (its logic is pinned in overview.test.ts).
    expect(await response!.text()).toMatch(/<script>\(function\(\)\{[^<]*setAttribute\("data-ui-theme"/);
    const atParse = await page.evaluate(() => (window as unknown as { __themeAtParse: string | null }).__themeAtParse);
    expect(atParse).toBe("light");
  });

  test("leaving the preview for today's page takes the preview's theme with it", async ({
    sessionPage: page,
  }) => {
    await serve(page, previewReport());
    await page.emulateMedia({ colorScheme: "light" });
    await page.goto(`${BASE}/network`);
    await expect(page.locator("html")).toHaveAttribute("data-ui-theme", "light");
    // The link on the placeholder, not the tab of the same name.
    const placeholder = page.getByRole("region", { name: "Network: coming next" });
    await placeholder.getByRole("link", { name: "Network", exact: true }).click();
    // Today's analysis route may compile on first visit under `next dev`.
    await expect(page).toHaveURL(`/analysis/${JOB_ID}/network`, { timeout: 30_000 });
    await expect(page.getByRole("heading", { name: /Domains/i }).first()).toBeVisible();
    await expect(page.locator("html:not([data-ui-theme])")).toHaveCount(1);
  });

  test("fits a phone without sideways scrolling", async ({ sessionPage: page }) => {
    await page.setViewportSize({ width: 390, height: 844 });
    await serve(page, previewReport());
    await page.goto(BASE);
    await expect(page.getByRole("heading", { name: /Top findings/ })).toBeVisible();
    const overflow = await page.evaluate(() => {
      const main = document.getElementById("main-content")!;
      return {
        doc: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        main: main.scrollWidth - main.clientWidth,
      };
    });
    expect(overflow).toEqual({ doc: 0, main: 0 });
  });
});
