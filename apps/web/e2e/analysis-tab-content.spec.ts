import { alerts, test, expect } from "./fixtures";
import { COMPLETED_JOB, JOB_ID, MALWARE_REPORT, REPORT } from "./report-fixture";
import type { ReportDetailDTO } from "@/lib/api";
import type { NetworkDomain, ProcessNode } from "@/types/malware-report";

/**
 * What the Behaviour, Network, Static & code and Indicators & detection tabs
 * hold, and how a reader moves through it (T-465).
 *
 * Each tab leads with the thing a reader picks first and opens details in
 * the side panel rather than a third level of nesting: a process on the
 * sample's path, a host and the requests it received, one part of the file's
 * structure, an indicator with its export decision and what else the report
 * says about it. Long lists are drawn ten rows at a time with "show more",
 * and an empty block says "Not found" in its place. What each block holds on
 * the populated fixture is pinned in analysis-tabs.spec.ts.
 */

const BASE = `/analysis/${JOB_ID}`;

async function serve(page: import("@playwright/test").Page, report: ReportDetailDTO = REPORT) {
  await page.route(`**/api/v1/reports/job/${JOB_ID}`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(report) }),
  );
  await page.route(`**/api/v1/jobs/${JOB_ID}`, (route) =>
    route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(COMPLETED_JOB) }),
  );
}

function withReport(over: Partial<NonNullable<ReportDetailDTO["malware_report"]>>): ReportDetailDTO {
  return { ...REPORT, malware_report: { ...MALWARE_REPORT, ...over } };
}

const proc = (pid: number, name: string, children: ProcessNode[] = [], extra: Partial<ProcessNode> = {}): ProcessNode => ({
  pid,
  ppid: 0,
  name,
  command_line: `${name} --run`,
  children,
  injected_into: [],
  ...extra,
});

test.describe("Behaviour", () => {
  test("the process tree opens the sample's path, folds the rest, and opens a process in the side panel", async ({
    sessionPage: page,
  }) => {
    await serve(
      page,
      withReport({
        dynamic: {
          ...MALWARE_REPORT.dynamic!,
          process_tree: [
            proc(4, "System", [
              proc(400, "services.exe", [proc(500, "svchost.exe"), proc(600, "spoolsv.exe")]),
              proc(700, "explorer.exe", [proc(1024, "invoice_scan.exe", [proc(1180, "cmd.exe")], { marked: true })]),
            ]),
          ],
        },
      }),
    );
    await page.goto(`${BASE}/behaviour`);
    const tree = page.getByRole("list", { name: "Process tree" });
    await expect(tree.getByRole("button", { name: "invoice_scan.exe", exact: true })).toBeVisible();
    await expect(tree.getByRole("button", { name: "cmd.exe", exact: true })).toBeVisible();
    // The benign branch is one row until a reader opens it.
    await expect(tree.getByRole("button", { name: "services.exe", exact: true })).toHaveCount(0);
    await tree.getByRole("button", { name: "3 other processes" }).click();
    await expect(tree.getByRole("button", { name: "services.exe", exact: true })).toBeVisible();

    const opener = tree.getByRole("button", { name: "invoice_scan.exe", exact: true });
    await opener.click();
    const drawer = page.getByRole("dialog", { name: "invoice_scan.exe (1024)" });
    await expect(drawer).toContainText("invoice_scan.exe --run");
    await expect(drawer).toContainText("marked as the sample's by the sandbox");
    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0);
    await expect(opener).toBeFocused();
    await expect(alerts(page)).toHaveCount(0);
  });

  test("behaviours are grouped by severity on the one n/5 scale, then by technique, each opening its evidence", async ({
    sessionPage: page,
  }) => {
    await serve(page);
    await page.goto(`${BASE}/behaviour`);
    const signatures = page.getByRole("group", { name: "Sandbox signatures" });
    // The fixture's sandbox reads 8 as High on its recorded scale; no scale is
    // recorded here, so the number stays the sandbox's own, unrated.
    await expect(signatures.getByText("Unrated").first()).toBeVisible();
    await expect(signatures.getByText("T1055")).toBeVisible();
    await signatures.getByRole("button", { name: "process_injection", exact: true }).click();
    await expect(page.getByRole("dialog")).toContainText("WriteProcessMemory into pid 640");
    await page.keyboard.press("Escape");
  });

  test("persistence and defence evasion are filtered views, and the old persistence link opens its view", async ({
    sessionPage: page,
  }) => {
    await serve(page);
    await page.goto(`${BASE}/behaviour#persistence`);
    const views = page.getByRole("group", { name: "Behaviour shown" });
    await expect(views.getByRole("button", { name: /^Persistence/ })).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator("#persistence")).toBeInViewport();
    await expect(page.getByText(/CurrentVersion\\Run\\UpdateSvc/)).toBeVisible();
    // The injection is defence evasion, not persistence.
    await expect(page.getByRole("button", { name: "process_injection", exact: true })).toHaveCount(0);

    await views.getByRole("button", { name: /^Defence evasion/ }).click();
    await expect(page.getByRole("button", { name: "process_injection", exact: true })).toBeVisible();
    await expect(page.getByText(/CurrentVersion\\Run\\UpdateSvc/)).toHaveCount(0);
    await expect(page.getByRole("list", { name: "Techniques by tactic" })).toContainText("Defense Evasion");

    await views.getByRole("button", { name: "All behaviour" }).click();
    await expect(page.getByText(/CurrentVersion\\Run\\UpdateSvc/)).toBeVisible();
    await expect(page.getByRole("button", { name: "process_injection", exact: true })).toBeVisible();
  });

  test("the recovered configuration is drawn once, on Static & code, and the technical analysis links there", async ({
    sessionPage: page,
  }) => {
    await serve(
      page,
      withReport({
        technical_analysis: {
          configuration: [{ key: "C2 host", value: "cdn.example-update.net", how_obtained: "decrypted", evidence_refs: [] }],
        },
      }),
    );
    await page.goto(`${BASE}/behaviour`);
    const panel = page.locator("#technical-analysis");
    await expect(panel.getByRole("cell", { name: "C2 host", exact: true })).toHaveCount(0);
    await panel.getByRole("link", { name: "Static & code › Decoded strings and configuration" }).click();
    await expect(page).toHaveURL(`${BASE}/static#decoded`);
    const decoded = page.locator("#decoded");
    await expect(decoded.getByRole("cell", { name: "C2 host", exact: true })).toBeVisible();
    await expect(decoded.getByRole("button", { name: "Copy configuration value C2 host" })).toBeVisible();
    await expect(decoded).toContainText("no evidence cited");
  });

  test("an ATT&CK technique opens its sources and corroboration in the side panel", async ({ sessionPage: page }) => {
    await serve(page);
    await page.goto(`${BASE}/behaviour`);
    const list = page.getByRole("list", { name: "Techniques by tactic" });
    await expect(list).toContainText("TA0005");
    await list.getByRole("button", { name: /T1055 Process Injection/ }).click();
    const drawer = page.getByRole("dialog", { name: "T1055 Process Injection" });
    await expect(drawer).toContainText("Tactic: Defense Evasion");
    await expect(drawer).toContainText("Claimed by");
  });
});

test.describe("Network", () => {
  test("a host opens what is known about it and the requests it received; a request opens its detail", async ({
    sessionPage: page,
  }) => {
    await serve(page);
    await page.goto(`${BASE}/network`);
    await page.getByRole("button", { name: "cdn.example-update.net", exact: true }).click();
    const host = page.getByRole("dialog", { name: "cdn.example-update.net" });
    await expect(host).toContainText("Newly registered domain");
    await expect(host).toContainText("185.199.110.153");
    await expect(host).toContainText("Requests to this host (1)");
    await expect(host).toContainText("https://cdn.example-update.net/gate.php");
    await page.keyboard.press("Escape");

    await page.getByRole("button", { name: "https://cdn.example-update.net/gate.php", exact: true }).click();
    const request = page.getByRole("dialog", { name: "HTTP request" });
    await expect(request).toContainText("POST");
    await expect(request).toContainText("200");
    await expect(request).toContainText("Mozilla/5.0");
    await page.keyboard.press("Escape");

    // DNS answers and the TLS fingerprints are tables of their own.
    await expect(page.getByRole("heading", { name: /^DNS/ })).toBeVisible();
    await expect(page.getByText("e7d705a3286e19ea42f587b344ee6865")).toBeVisible();
    await expect(alerts(page)).toHaveCount(0);
  });

  test("a long table is drawn ten rows at a time, and a host nobody looked up says so", async ({ sessionPage: page }) => {
    const domains: NetworkDomain[] = Array.from({ length: 12 }, (_, i) => ({
      ...MALWARE_REPORT.network!.domains[0],
      fqdn: `host${i}.example.test`,
      reputation: null,
    }));
    await serve(page, withReport({ network: { ...MALWARE_REPORT.network!, domains } }));
    await page.goto(`${BASE}/network`);
    const dns = page.locator("section", { has: page.getByRole("heading", { name: /^DNS/ }) });
    await expect(dns.getByText(/^host\d+\.example\.test$/)).toHaveCount(10);
    await dns.getByRole("button", { name: "Show 2 more" }).click();
    await expect(dns.getByText(/^host\d+\.example\.test$/)).toHaveCount(12);
    await expect(page.getByText("Not looked up").first()).toBeVisible();
  });
});

test.describe("Static & code", () => {
  test("the file's structure shows one part at a time, and strings filter by kind and search", async ({
    sessionPage: page,
  }) => {
    await serve(page);
    await page.goto(`${BASE}/static`);
    const tabs = page.getByRole("tablist");
    await expect(tabs).toHaveAttribute("aria-orientation", "vertical");
    await expect(page.getByRole("tab", { name: /^Sections/ })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("cell", { name: /^\.text/ })).toBeVisible();
    await page.getByRole("tab", { name: /^Resources/ }).click();
    await expect(page.getByRole("tabpanel")).toContainText("Not found");
    await expect(page.getByRole("cell", { name: /^\.text/ })).toHaveCount(0);

    const strings = page.locator("#strings");
    await expect(strings.getByText("cdn.example-update.net")).toBeVisible();
    await strings.getByRole("button", { name: /^ip 1$/ }).click();
    await expect(strings.getByText("cdn.example-update.net")).toHaveCount(0);
    await expect(strings.getByText("185.199.110.153")).toBeVisible();
    await strings.getByRole("button", { name: /^All/ }).click();
    await strings.getByRole("searchbox", { name: "Search strings" }).fill("C2 candidate");
    await expect(strings.getByText("185.199.110.153")).toHaveCount(0);
    await expect(strings.getByText("cdn.example-update.net")).toBeVisible();

    // The build and packing facts sit with the file's identity.
    await expect(page.locator("#identity")).toContainText("UPX (modified)");
    // Blocks the run did not fill keep their place.
    await expect(page.locator("#decoded")).toContainText("Not found");
    await expect(page.locator("#functions")).toContainText("Not found");
  });
});

test.describe("Indicators & detection", () => {
  test("the indicator browser narrows by type, search and export decision, and opens a value with its reason", async ({
    sessionPage: page,
  }) => {
    await serve(page);
    await page.goto(`${BASE}/indicators`);
    const browser = page.getByTestId("indicators-panel");
    await expect(browser).toContainText("1 published · 1 withheld");
    await browser.getByRole("button", { name: "IPv4 1" }).click();
    await expect(browser.getByRole("button", { name: "8.8.8.8", exact: true })).toBeVisible();
    await expect(browser.getByRole("button", { name: /^[0-9a-f]{64}$/ })).toHaveCount(0);
    await browser.getByRole("button", { name: /^All/ }).click();
    await browser.getByRole("combobox", { name: "Export decision" }).selectOption("published");
    await expect(browser.getByRole("button", { name: "8.8.8.8", exact: true })).toHaveCount(0);
    await browser.getByRole("combobox", { name: "Export decision" }).selectOption("all");
    await browser.getByRole("searchbox", { name: "Search indicators" }).fill("resolver");
    await expect(browser.getByRole("button", { name: /^[0-9a-f]{64}$/ })).toHaveCount(0);

    // Every value has its own copy control.
    await expect(browser.getByRole("button", { name: "Copy indicator 8.8.8.8" })).toBeVisible();
    await browser.getByRole("button", { name: "8.8.8.8", exact: true }).click();
    const drawer = page.getByRole("dialog", { name: "IPv4" });
    await expect(drawer).toContainText("withheld");
    await expect(drawer).toContainText("it is a public DNS resolver");
    await expect(drawer).toContainText("Related findings");
    await page.keyboard.press("Escape");

    await browser.getByRole("searchbox", { name: "Search indicators" }).fill("");
    await browser.getByRole("button", { name: /^[0-9a-f]{64}$/ }).click();
    await expect(page.getByRole("dialog", { name: "SHA-256" })).toContainText("Named in the verdict");
  });

  test("generated rules are one list, each with its own copy and download, its body in the side panel", async ({
    sessionPage: page,
  }) => {
    await serve(page);
    await page.goto(`${BASE}/indicators`);
    const rules = page.locator("#generated-rules");
    await expect(rules.getByRole("button", { name: "Copy yara rule Maljan_AgentTesla_Injection" })).toBeVisible();
    const download = page.waitForEvent("download");
    await rules.getByRole("button", { name: "Download yara rule Maljan_AgentTesla_Injection" }).click();
    expect((await download).suggestedFilename()).toBe("Maljan_AgentTesla_Injection.yar");
    await rules.getByRole("button", { name: "Maljan_AgentTesla_Injection", exact: true }).click();
    await expect(page.getByRole("dialog")).toContainText('$a = "VirtualAllocEx"');
  });

  test("the STIX objects are drawn on request", async ({ sessionPage: page }) => {
    await serve(page);
    await page.goto(`${BASE}/indicators`);
    const toggle = page.getByRole("button", { name: "STIX 2.1 objects" });
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await toggle.click();
    await expect(page.getByRole("group", { name: "How the bundle is shown" })).toBeVisible();
  });
});

test.describe("one screen, plain words", () => {
  for (const tab of ["/behaviour", "/network", "/static", "/indicators"]) {
    test(`${tab} holds at most one primary button and no capitalised block title`, async ({ sessionPage: page }) => {
      await serve(page);
      await page.goto(`${BASE}${tab}`);
      const content = page.getByTestId("analysis-content");
      await expect(content.locator("h2").first()).toBeVisible();
      expect(await content.locator('[data-variant="primary"]').count()).toBeLessThanOrEqual(1);
      const shouting = await content.locator("h2, h3").evaluateAll((els) =>
        els.filter((el) => getComputedStyle(el).textTransform === "uppercase").map((el) => el.textContent),
      );
      expect(shouting).toEqual([]);
    });
  }
});
