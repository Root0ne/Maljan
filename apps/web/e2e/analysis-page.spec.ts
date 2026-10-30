import { alerts, test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, MALWARE_REPORT, REPORT } from "./report-fixture";
import type { ReportDetailDTO } from "@/lib/api";

/**
 * The analysis page: one sticky header and six tabs.
 *
 * What is pinned here is what the layout promises a reader: the verdict,
 * confidence and file in the first glance; six tabs, each its own URL; the
 * evidence behind a finding one click away in a side panel that gives focus
 * back; one Export menu grouped by intent; remarks only when the run is not
 * whole; no internal words outside Evidence; a header of at most six
 * controls and an Overview of at most ten above the fold; light and dark
 * themes; and a page that fits a phone without sideways scrolling. What
 * each tab holds is pinned in analysis-tabs.spec.ts.
 */

const BASE = `/analysis/${JOB_ID}`;

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

test.describe("Analysis page", () => {
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
    const text = await page.getByTestId("analysis-page").innerText();
    expect(text).not.toMatch(/\b(ledger|judge|producer|nudge)\b/i);
    expect(text).not.toMatch(/\bev_\d+/);
  });

  test("the header holds at most six controls", async ({ sessionPage: page }) => {
    await serve(page, previewReport());
    await page.goto(BASE);
    const header = page.getByRole("region", { name: "Analysis summary" });
    await expect(header.getByRole("heading", { level: 1 })).toBeVisible();
    const controls = header.locator("a:visible, button:visible, input:visible, select:visible, textarea:visible");
    expect(await controls.count()).toBeLessThanOrEqual(6);
  });

  test("Overview has at most ten controls above the fold at 1280 by 900", async ({ sessionPage: page }) => {
    await page.setViewportSize({ width: 1280, height: 900 });
    await serve(page, previewReport());
    await page.goto(BASE);
    await expect(page.getByRole("heading", { name: /Top findings/ })).toBeVisible();
    // The app's own navigation, the header and the tabs are not counted: only
    // what Overview itself puts in the first screen.
    const above = await page.getByTestId("analysis-content").evaluate((root) => {
      const fold = window.innerHeight;
      return Array.from(root.querySelectorAll<HTMLElement>("a, button, input, select, textarea, [tabindex]")).filter(
        (el) => {
          const box = el.getBoundingClientRect();
          return box.width > 0 && box.height > 0 && box.top < fold;
        },
      ).length;
    });
    expect(above).toBeLessThanOrEqual(10);
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
      "This run generated no MISP attributes",
    );
    // The first usable item has focus, and Escape gives it back to the button.
    await expect(menu.getByRole("menuitem").first()).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(menu).toHaveCount(0);
    await expect(button).toBeFocused();

    await button.click();
    const download = page.waitForEvent("download");
    await page.getByRole("menuitem", { name: /Indicator list/ }).click();
    expect((await download).suggestedFilename()).toMatch(/^maljan-[0-9a-f]{12}-iocs\.json$/);
  });

  test("each tab is its own URL and holds the content it names", async ({ sessionPage: page }) => {
    await serve(page, previewReport());
    await page.goto(BASE);
    const nav = page.getByRole("navigation", { name: "Analysis sections" });
    await nav.getByRole("link", { name: /^Network/ }).click();
    await expect(page).toHaveURL(`${BASE}/network`);
    await expect(nav.getByRole("link", { name: /^Network/ })).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("heading", { name: /Domains/i }).first()).toBeVisible();

    await nav.getByRole("link", { name: /^Evidence/ }).click();
    await expect(page).toHaveURL(`${BASE}/evidence`);
    await expect(page.getByRole("heading", { name: /Evidence records/ })).toBeVisible();
  });

  test("every finished analysis offers the same six tabs, with a count where the report gives one", async ({
    sessionPage: page,
  }) => {
    await serve(page, previewReport());
    await page.goto(`${BASE}/static`);
    const nav = page.getByRole("navigation", { name: "Analysis sections" });
    await expect(nav.getByRole("link")).toHaveCount(6);
    await expect(nav.getByRole("link", { name: /^Static & code/ })).toHaveAttribute("aria-current", "page");
    // The badge is said as "n items" beside the label.
    await expect(nav.getByRole("link", { name: /^Evidence 4 items$/ })).toBeVisible();
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

  test("every tab of the analysis carries the theme; leaving the analysis takes it away", async ({
    sessionPage: page,
  }) => {
    await serve(page, previewReport());
    await page.emulateMedia({ colorScheme: "light" });
    await page.goto(`${BASE}/network`);
    await expect(page.locator("html")).toHaveAttribute("data-ui-theme", "light");
    await page.getByRole("navigation", { name: "Analysis sections" }).getByRole("link", { name: /^Evidence/ }).click();
    await expect(page).toHaveURL(`${BASE}/evidence`);
    await expect(page.locator("html")).toHaveAttribute("data-ui-theme", "light");
    // The other pages keep their own look.
    await page.getByRole("link", { name: "Dashboard" }).click();
    await expect(page).toHaveURL("/dashboard", { timeout: 30_000 });
    await expect(page.locator("html:not([data-ui-theme])")).toHaveCount(1);
  });

  test("the preview's address lands on the page it became", async ({ sessionPage: page }) => {
    await serve(page, previewReport());
    await page.goto(`/preview/analysis/${JOB_ID}`);
    await expect(page).toHaveURL(BASE, { timeout: 20_000 });
    await page.goto(`/preview/analysis/${JOB_ID}/indicators`);
    await expect(page).toHaveURL(`${BASE}/indicators`, { timeout: 20_000 });
  });

  /* The pipeline's own words, the evidence store's ids and the raw shapes
   * stay on Evidence, where a reader goes to check the work. */
  for (const tab of ["", "/behaviour", "/network", "/static", "/indicators"]) {
    test(`${tab || "/ (overview)"} speaks the reader's words, not the pipeline's`, async ({ sessionPage: page }) => {
      await serve(page, previewReport());
      await page.goto(`${BASE}${tab}`);
      const content = page.getByTestId("analysis-content");
      await expect(content.locator("h2").first()).toBeVisible();
      const text = await page.getByTestId("analysis-page").innerText();
      expect(text).not.toMatch(/\b(ledger|judge|producer|nudge|report model)\b/i);
      expect(text).not.toMatch(/RAG Candidates|Sections no tab draws|MALJAN_[A-Z_]+|Platform check|\bMeasured\b/);
      expect(text).not.toMatch(/\bev_\d+/);
      // No tooltip is a dumped object.
      const dumped = await page.locator('[title^="{"]').count();
      expect(dumped).toBe(0);
    });
  }

  test("every download the page offered before is in the one Export menu", async ({ sessionPage: page }) => {
    await serve(page, previewReport());
    await page.goto(BASE);
    await page.getByRole("button", { name: "Export" }).click();
    const menu = page.getByRole("menu", { name: "Export" });
    for (const name of [
      /^Report \(PDF\)/,
      /^Report \(HTML\)/,
      /^Report \(Markdown\)/,
      /^Indicator list/,
      /^STIX 2\.1 bundle/,
      /^Evidence bundle \(HTML\)/,
      /^Evidence bundle \(JSON\)/,
      /^MISP attributes/,
      /^ATT&CK Navigator layer/,
      /^YARA rules/,
      /^Full analysis \(JSON\)/,
      /^ATT&CK techniques \(JSON\)/,
      /^Discussion timeline \(JSON\)/,
    ]) {
      await expect(menu.getByRole("menuitem", { name })).toHaveCount(1);
    }
    // The report's HTML says the bundle downloads beside it, so its links resolve.
    await expect(menu.getByRole("menuitem", { name: /^Report \(HTML\)/ })).toContainText(
      "save the evidence bundle (HTML) beside it",
    );
    await page.keyboard.press("Escape");

    // The bundle saves under exactly the names the analyst report links to.
    for (const [name, file] of [
      [/^Evidence bundle \(HTML\)/, "evidence-bundle.html"],
      [/^Evidence bundle \(JSON\)/, "evidence-bundle.json"],
    ] as const) {
      await page.getByRole("button", { name: "Export" }).click();
      const download = page.waitForEvent("download");
      await page.getByRole("menuitem", { name }).click();
      expect((await download).suggestedFilename()).toBe(file);
    }

    // The detection block exports nothing a second time: the bundle, the
    // Navigator layer and one file per rule kind are the menu's. A rule
    // keeps its own copy and download, and the graph its picture.
    await page.goto(`${BASE}/indicators`);
    await expect(page.getByRole("heading", { name: /Generated detection rules/ })).toBeVisible();
    const block = page.locator("#detection");
    await expect(block.getByRole("button", { name: "Navigator layer" })).toHaveCount(0);
    await expect(block.getByRole("button", { name: "Download", exact: true })).toHaveCount(0);
    await expect(block.getByRole("button", { name: /bundle$/ })).toHaveCount(0);
    await expect(block.getByText("Every rule of one kind as one file: Export, at the top of the page.")).toBeVisible();
  });

  test("an operator's own agent and server are views under Evidence, never a seventh tab", async ({
    sessionPage: page,
  }) => {
    const report = previewReport();
    report.malware_report = {
      ...report.malware_report!,
      sections: [
        ...(report.malware_report!.sections ?? []),
        {
          key: "tool_hunt_notes",
          title: "Hunt notes",
          kind: "list",
          columns: [],
          rows: [],
          items: ["mutex held across reboots"],
          text: "",
          evidence_ids: ["ev_0001"],
          source: "agent:hunter",
        },
        {
          key: "tool_mystery_scan",
          title: "Mystery scan",
          kind: "table",
          columns: ["Field", "Value"],
          rows: [["entropy", "7.9"]],
          items: [],
          text: "",
          evidence_ids: ["ev_0002"],
          source: "tool:mystery_scan",
          source_server: "mystery",
        },
      ],
    };
    await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
      route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(report) }),
    );
    await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          ...COMPLETED_JOB,
          roster: {
            agents: [{ key: "hunter", label: "Hunter", role: "generic", stages: ["analysis"] }],
            stages: [{ key: "analysis", kind: "analysis", agents: ["hunter"] }],
            servers: { mystery: "Mystery Box" },
          },
        }),
      }),
    );
    await page.goto(`${BASE}/evidence`);
    await expect(page.getByRole("navigation", { name: "Analysis sections" }).getByRole("link")).toHaveCount(6);
    const views = page.getByRole("navigation", { name: "Evidence views" });
    await expect(views.getByRole("link")).toHaveText(["Records", "Analyst discussion", "Hunter", "Mystery Box"]);
    await views.getByRole("link", { name: "Hunter" }).click();
    await expect(page).toHaveURL(`${BASE}/evidence/agent/hunter`);
    await expect(page.getByText("mutex held across reboots")).toBeVisible();
    await views.getByRole("link", { name: "Mystery Box" }).click();
    await expect(page).toHaveURL(`${BASE}/evidence/server/mystery`);
    await expect(page.getByText("7.9")).toBeVisible();
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
