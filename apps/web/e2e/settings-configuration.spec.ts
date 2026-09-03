import { test, expect } from "./fixtures";
import { MOCK_USER } from "./mocks";

/**
 * The admin-only Configuration tab under /settings.
 *
 * `authenticatedPage`'s default fixture user is role `"analyst"`, so every
 * test that needs to actually see the tab's contents overrides
 * `mockOptions.user` to `role: "admin"` via `test.use` — the pattern
 * `mocks.ts` documents for the `auth/me` override. The non-admin describe
 * block deliberately leaves the default in place, since that gated state is
 * exactly what it is testing.
 *
 * Fixture data (`e2e/mocks.ts`): two groups — "Negotiation" (a `default`-
 * sourced int and a `ui`-sourced int, so per-row/group reset visibility has
 * both a positive and a negative case in one group) and "Providers" (one
 * `env`-sourced, currently-set secret with probe `"llm"`).
 */

test.describe("Settings → Configuration (admin)", () => {
  test.use({ mockOptions: { user: { ...MOCK_USER, role: "admin" } } });

  test("shows the tab and renders the schema's groups", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();

    await expect(page.getByRole("button", { name: "Negotiation", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Providers", exact: true })).toBeVisible();
    await expect(page.getByText("core.negotiation.max_iterations")).toBeVisible();
  });

  test("stages a change, shows the pending bar, and Apply → Confirm sends one PATCH with the applies summary", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await expect(page.getByText("core.negotiation.max_iterations")).toBeVisible();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: { applied: ["core.negotiation.max_iterations"], applies: { next_job: 1 } },
        });
      }
      return r.fallback();
    });

    const field = page.locator("#setting-core\\.negotiation\\.max_iterations input[type=number]");
    await field.fill("7");
    await expect(page.getByText("1 change pending")).toBeVisible();

    await page.getByRole("button", { name: "Apply" }).click();
    await expect(page.getByText("takes effect on the next analysis")).toBeVisible();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    await expect(page.getByText(/Applied 1 setting/)).toContainText("on the next analysis");
    expect(patches).toEqual([{ changes: { "core.negotiation.max_iterations": 7 } }]);
  });

  test("a 422 from PATCH maps the message to the field and shows no success status", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();

    await page.route("**/api/v1/settings", (r) =>
      r.request().method() === "PATCH"
        ? r.fulfill({
            status: 422,
            json: { errors: { "core.negotiation.max_iterations": "Input should be greater than 0" } },
          })
        : r.fallback()
    );

    const row = page.locator("#setting-core\\.negotiation\\.max_iterations");
    await row.locator("input[type=number]").fill("0");
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    await expect(row.getByRole("alert")).toContainText("greater than 0");
    await expect(page.getByText(/Applied \d+ setting/)).toHaveCount(0);
  });

  test("a secret never renders its value and shows no password input until editing", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Providers", exact: true }).click();

    await expect(page.getByText("set · …1234 · env")).toBeVisible();
    await expect(page.locator("input[type=password]")).toHaveCount(0);
  });

  test("setting a new secret value sends it in the PATCH body exactly once", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Providers", exact: true }).click();

    await page.getByRole("button", { name: "Set new value" }).click();
    await page.locator("input[type=password]").fill("sk-new-secret-value");
    await page.getByRole("button", { name: "Stage" }).click();
    await expect(page.getByText("new value staged")).toBeVisible();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: { applied: ["core.llm.openai.api_key"], applies: { next_job: 1 } },
        });
      }
      return r.fallback();
    });

    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    await expect(page.getByText(/Applied 1 setting/)).toBeVisible();

    expect(patches).toEqual([
      { changes: { "core.llm.openai.api_key": "sk-new-secret-value" } },
    ]);
  });

  test("clearing a set secret sends null in the PATCH body", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Providers", exact: true }).click();

    await page.getByRole("button", { name: "Clear" }).click();
    await expect(page.getByText("will be cleared")).toBeVisible();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: { applied: ["core.llm.openai.api_key"], applies: { next_job: 1 } },
        });
      }
      return r.fallback();
    });

    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    await expect(page.getByText(/Applied 1 setting/)).toBeVisible();

    expect(patches).toEqual([{ changes: { "core.llm.openai.api_key": null } }]);
  });

  test("per-row reset only appears for a UI-sourced value and calls DELETE on that key", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();

    const uiRow = page.locator("#setting-core\\.negotiation\\.retry_delay");
    const defaultRow = page.locator("#setting-core\\.negotiation\\.max_iterations");
    await expect(uiRow.getByRole("button", { name: "Reset to env" })).toBeVisible();
    await expect(defaultRow.getByRole("button", { name: "Reset to env" })).toHaveCount(0);

    let deleteUrl: string | null = null;
    await page.route("**/api/v1/settings/*", (r) => {
      if (r.request().method() === "DELETE") {
        deleteUrl = r.request().url();
        return r.fulfill({ json: { reset: ["core.negotiation.retry_delay"] } });
      }
      return r.fallback();
    });

    await uiRow.getByRole("button", { name: "Reset to env" }).click();
    await expect.poll(() => deleteUrl).toContain("/api/v1/settings/core.negotiation.retry_delay");
  });

  test("group reset only appears when a value in the group is UI-sourced, and calls DELETE with the group query", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();

    // Negotiation (default active group) has a "ui"-sourced entry.
    await expect(page.getByRole("button", { name: "Reset group to env" })).toBeVisible();

    // Providers has none — no button once its section is the one showing.
    await page.getByRole("button", { name: "Providers", exact: true }).click();
    await expect(page.getByRole("button", { name: "Reset group to env" })).toHaveCount(0);

    await page.getByRole("button", { name: "Negotiation", exact: true }).click();
    let deleteUrl: string | null = null;
    await page.route("**/api/v1/settings?**", (r) => {
      deleteUrl = r.request().url();
      return r.fulfill({ json: { reset: ["core.negotiation.retry_delay"] } });
    });

    await page.getByRole("button", { name: "Reset group to env" }).click();
    await expect.poll(() => deleteUrl).toContain("group=negotiation");
  });

  test("Test connection calls the probe endpoint and renders ok/latency", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Providers", exact: true }).click();

    let probeUrl: string | null = null;
    await page.route("**/api/v1/settings/test/*", (r) => {
      probeUrl = r.request().url();
      return r.fulfill({
        json: { ok: true, latency_ms: 120, detail: "Connected as gpt-4o", models: ["gpt-4o"] },
      });
    });

    await page.getByRole("button", { name: "Test connection & fetch models" }).click();
    await expect(page.getByText(/ok · 120 ms · Connected as gpt-4o/)).toBeVisible();
    expect(probeUrl).toContain("/api/v1/settings/test/llm");
  });

  test("export calls the export endpoint (no download assertion)", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();

    let exportRequested = false;
    await page.route("**/api/v1/settings/export", (r) => {
      exportRequested = true;
      return r.fulfill({
        status: 200,
        contentType: "text/plain",
        body: "CORE_NEGOTIATION_RETRY_DELAY=10\n",
      });
    });

    await page.getByRole("button", { name: "Export overrides (.env)" }).click();
    await expect.poll(() => exportRequested).toBe(true);
    await expect(page.getByText("Overrides downloaded as maljan-settings.env")).toBeVisible();
  });

  test("the search box narrows the visible rows", async ({ authenticatedPage: page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();

    await page.getByLabel("Search settings").fill("openai");
    await expect(page.getByText("OpenAI-compatible API key")).toBeVisible();
    await expect(page.getByText("Max iterations")).toHaveCount(0);
  });

  test("a reset failure shows a dismissible banner and the tab stays mounted", async ({
    authenticatedPage: page,
  }) => {
    const pageErrors: Error[] = [];
    page.on("pageerror", (err) => pageErrors.push(err));

    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();

    // `core.negotiation.retry_delay` is the "ui"-sourced key in the mock —
    // the only one of the two negotiation entries that actually renders a
    // "Reset to env" button to click (see the "per-row reset" test above).
    await page.route("**/api/v1/settings/core.negotiation.retry_delay", (r) =>
      r.request().method() === "DELETE"
        ? r.fulfill({ status: 500, json: { detail: "reset failed: database unavailable" } })
        : r.fallback()
    );

    const uiRow = page.locator("#setting-core\\.negotiation\\.retry_delay");
    await uiRow.getByRole("button", { name: "Reset to env" }).click();

    const banner = page.getByRole("alert").filter({ hasText: "reset failed" });
    await expect(banner).toBeVisible();
    await expect(banner.getByRole("button", { name: "Dismiss error" })).toBeVisible();

    // The failure is scoped to the banner — the rest of the tab, including
    // an unrelated row, is still on the page.
    await expect(page.locator("#settings-search")).toBeVisible();
    await expect(page.getByText("core.negotiation.max_iterations")).toBeVisible();

    await banner.getByRole("button", { name: "Dismiss error" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "reset failed" })).toHaveCount(0);

    expect(pageErrors).toHaveLength(0);
  });

  test("clearing a required number field un-stages the edit instead of reverting it", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();

    const field = page.locator("#setting-core\\.negotiation\\.max_iterations input[type=number]");
    const pendingBar = page.getByText("1 change pending");
    const requiredAlert = page.getByText(/Required — enter a value/);

    await field.fill("7");
    await expect(pendingBar).toBeVisible();

    await field.fill("");
    await expect(requiredAlert).toBeVisible();
    await expect(page.getByText(/change.*pending/)).toHaveCount(0);
    await expect(field).toHaveValue("");

    await field.fill("9");
    await expect(pendingBar).toBeVisible();
    await expect(requiredAlert).toHaveCount(0);
  });
});

test.describe("Settings → Configuration (non-admin)", () => {
  test("the tab is disabled with 'Admin role required' and cannot be opened", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");

    const tab = page.getByRole("button", { name: "Configuration" });
    await expect(tab).toBeDisabled();
    await expect(tab).toHaveAttribute("title", "Admin role required");
    await expect(page.locator("#settings-search")).toHaveCount(0);
  });
});
