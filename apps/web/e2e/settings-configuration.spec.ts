import { test, expect } from "./fixtures";
import { MOCK_USER } from "./mocks";

/**
 * The admin-only Configuration console at
 * `/settings/configuration/<section>/<group>`.
 *
 * `authenticatedPage`'s default fixture user is role `"analyst"`, so every
 * test that needs to actually see the console overrides `mockOptions.user`
 * to `role: "admin"` via `test.use` — the pattern `mocks.ts` documents for
 * the `auth/me` override. The non-admin describe block deliberately leaves
 * the default in place, since that gated state is exactly what it is
 * testing.
 *
 * Fixture data (`e2e/mocks.ts`): "Negotiation" (`negotiation`, section
 * `agents`) has a `default`-sourced int, a `ui`-sourced int, a `ui`-sourced
 * `advanced: true` int (so the "Advanced" fold's default-open rule has a
 * positive case to prove), and a `list` field; "Providers" (`providers`,
 * section `models`) has one `env`-sourced, currently-set secret with probe
 * `"llm"` plus the provider selector, which shares that same probe id with
 * the "LLM & model" group's (`llm`, section `models`) Ollama base URL.
 *
 * Rail entries are links now (`getByRole("link", ...)`), and a tab switch
 * that must survive with staged edits intact clicks one rather than calling
 * `page.goto` — a full navigation would remount the console and drop
 * `pending`. `page.goto` is used only for a spec's first arrival at a group.
 */

const NEGOTIATION_PATH = "/settings/configuration/agents/negotiation";
const PROVIDERS_PATH = "/settings/configuration/models/providers";
const LLM_PATH = "/settings/configuration/models/llm";
const SANDBOX_PATH = "/settings/configuration/tools/sandbox";
const STATIC_PATH = "/settings/configuration/tools/static";
const PROFILES_PATH = "/settings/configuration/agents/profiles";
const SEARCH_PATH = "/settings/configuration/search";

test.describe("Settings → Configuration (admin)", () => {
  test.use({ mockOptions: { user: { ...MOCK_USER, role: "admin" } } });

  test("shows the console and renders the schema's groups", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    await expect(page.getByRole("link", { name: /^Negotiation/ })).toBeVisible();
    await expect(page.getByRole("link", { name: /^Providers/ })).toBeVisible();
    await expect(page.getByText("core.negotiation.max_iterations")).toBeVisible();
  });

  test("a deep link to a group opens it directly", async ({ authenticatedPage: page }) => {
    await page.goto(NEGOTIATION_PATH);

    await expect(page.getByRole("heading", { name: "Negotiation", level: 2 })).toBeVisible();
    await expect(page.getByRole("link", { name: /^Negotiation/ })).toHaveAttribute(
      "aria-current",
      "page"
    );
  });

  test("staging a value shows the rail badge for its group", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    await page
      .locator("#setting-core\\.negotiation\\.max_iterations input[type=number]")
      .fill("7");

    const link = page.getByRole("link", { name: /^Negotiation/ });
    // The visible badge is aria-hidden; the accessible name carries the
    // sr-only count text instead, so a screen reader hears "1 unsaved
    // changes" rather than a bare digit.
    await expect(link).toHaveAccessibleName(/1 unsaved changes/);
  });

  test("stages a change, shows the pending bar, and Review → Confirm sends one PATCH with the applies summary", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);
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
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");

    await page.getByRole("button", { name: "Review" }).click();
    await expect(page.getByText("takes effect on the next analysis")).toBeVisible();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    await expect(page.getByText(/Applied 1 setting/)).toContainText("on the next analysis");
    expect(patches).toEqual([{ changes: { "core.negotiation.max_iterations": 7 } }]);
  });

  test("a 422 from PATCH maps the message to the field and shows no success status", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

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
    await page.getByRole("button", { name: "Review" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    await expect(row.getByRole("alert")).toContainText("greater than 0");
    await expect(page.getByText(/Applied \d+ setting/)).toHaveCount(0);
  });

  test("a secret never renders its value and shows no password input until editing", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(PROVIDERS_PATH);

    await expect(page.getByText("set · …1234 · env")).toBeVisible();
    await expect(page.locator("input[type=password]")).toHaveCount(0);
  });

  test("setting a new secret value sends it in the PATCH body exactly once", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(PROVIDERS_PATH);

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

    await page.getByRole("button", { name: "Review" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    await expect(page.getByText(/Applied 1 setting/)).toBeVisible();

    expect(patches).toEqual([
      { changes: { "core.llm.openai.api_key": "sk-new-secret-value" } },
    ]);
  });

  test("clearing a set secret sends null in the PATCH body", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(PROVIDERS_PATH);

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

    await page.getByRole("button", { name: "Review" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    await expect(page.getByText(/Applied 1 setting/)).toBeVisible();

    expect(patches).toEqual([{ changes: { "core.llm.openai.api_key": null } }]);
  });

  test("per-row reset only appears for a UI-sourced value and calls DELETE on that key", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    const uiRow = page.locator("#setting-core\\.negotiation\\.retry_delay");
    const defaultRow = page.locator("#setting-core\\.negotiation\\.max_iterations");
    await expect(uiRow.getByRole("button", { name: "Remove override" })).toBeVisible();
    await expect(defaultRow.getByRole("button", { name: "Remove override" })).toHaveCount(0);

    let deleteUrl: string | null = null;
    await page.route("**/api/v1/settings/*", (r) => {
      if (r.request().method() === "DELETE") {
        deleteUrl = r.request().url();
        return r.fulfill({ json: { reset: ["core.negotiation.retry_delay"] } });
      }
      return r.fallback();
    });

    await uiRow.getByRole("button", { name: "Remove override" }).click();
    await expect.poll(() => deleteUrl).toContain("/api/v1/settings/core.negotiation.retry_delay");
  });

  test("group reset only appears when a value in the group is UI-sourced, and calls DELETE with the group query", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    // Negotiation has two ui-sourced entries (retry_delay, advanced_knob).
    await expect(
      page.getByRole("button", { name: /Remove all overrides in this group/ })
    ).toBeVisible();

    // Providers has none — no button once its group is the one showing.
    await page.goto(PROVIDERS_PATH);
    await expect(
      page.getByRole("button", { name: /Remove all overrides in this group/ })
    ).toHaveCount(0);

    await page.goto(NEGOTIATION_PATH);
    let deleteUrl: string | null = null;
    await page.route("**/api/v1/settings?**", (r) => {
      deleteUrl = r.request().url();
      return r.fulfill({
        json: { reset: ["core.negotiation.retry_delay", "core.negotiation.advanced_knob"] },
      });
    });

    await page.getByRole("button", { name: /Remove all overrides in this group/ }).click();
    await page.getByRole("button", { name: /Remove \d+ overrides/ }).click();
    await expect.poll(() => deleteUrl).toContain("group=negotiation");
  });

  /* Task 21: "Profiles" is carved out of the backend `agents` group, so a
   * group-wide DELETE from that page would also remove the overrides that
   * belong to the *Agents* page — more than the dialog counted. Both sides of
   * a virtual split reset per key instead. */
  test("a virtual group's reset deletes only its own keys, not the whole backend group", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(PROFILES_PATH);

    const deletedKeys: string[] = [];
    let groupDeletes = 0;
    await page.route("**/api/v1/settings/*", (r) => {
      if (r.request().method() === "DELETE") {
        const key = new URL(r.request().url()).pathname.split("/").pop() ?? "";
        deletedKeys.push(key);
        return r.fulfill({ json: { reset: [key] } });
      }
      return r.fallback();
    });
    await page.route("**/api/v1/settings?**", (r) => {
      groupDeletes += 1;
      return r.fulfill({ json: { reset: [] } });
    });

    // Only `core.agents.profile` is this page's own ui-sourced key —
    // `core.react_agent_timeout` is ui-sourced too but belongs to the Agents
    // page, and must survive.
    const reset = page.getByRole("button", { name: "Remove all overrides in this group (1)" });
    await expect(reset).toBeVisible();
    await reset.click();
    await page.getByRole("button", { name: /Remove 1 overrides/ }).click();

    await expect.poll(() => deletedKeys).toEqual(["core.agents.profile"]);
    expect(groupDeletes).toBe(0);
  });

  test("the group-reset dialog appears and cancelling with 'Keep them' sends no DELETE", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    let deleteCalled = false;
    await page.route("**/api/v1/settings?**", (r) => {
      deleteCalled = true;
      return r.fulfill({ json: { reset: [] } });
    });

    await page.getByRole("button", { name: /Remove all overrides in this group/ }).click();
    const dialog = page.getByRole("dialog", { name: "Remove overrides" });
    await expect(dialog).toBeVisible();

    await dialog.getByRole("button", { name: "Keep them" }).click();
    await expect(dialog).toHaveCount(0);
    expect(deleteCalled).toBe(false);
  });

  test("Test connection calls the probe endpoint and renders ok/latency", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(PROVIDERS_PATH);

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

  test("a probe result disappears once one of its inputs is staged afterwards", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(PROVIDERS_PATH);

    await page.route("**/api/v1/settings/test/*", (r) =>
      r.fulfill({ json: { ok: true, latency_ms: 5, detail: "ok", models: [], tools: null } })
    );

    await page.getByRole("button", { name: "Test connection & fetch models" }).click();
    const result = page.getByText(/ok · 5 ms · ok/);
    await expect(result).toBeVisible();

    // Staging a new provider is one of the "llm" probe's own inputs — the
    // stale result must be dropped rather than going on describing a press
    // that would now send something different.
    await page.getByRole("combobox", { name: "Provider" }).selectOption("ollama");
    await expect(result).toHaveCount(0);
  });

  test("the probe body carries every staged input it reads, including another group's", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(LLM_PATH);

    // Stage the Ollama base URL in the "LLM & model" group. `getByLabel` is
    // ambiguous on this page: `FieldRow` points the title at the input with
    // `htmlFor` *and* names the widget's wrapper with `aria-labelledby`, so
    // the accessible name matches the control and its group. Address the
    // control by role, the way the rest of this spec does.
    await page
      .getByRole("textbox", { name: "Ollama base URL" })
      .fill("http://10.0.0.9:11434");

    // ...then run the probe from the *Providers* group, where the staged
    // provider lives. A group-local key list would drop the base URL and the
    // backend would silently probe the stored one. Switching groups here has
    // to be a rail click, not a fresh `page.goto` — a full navigation would
    // remount the console and drop the base URL edit just staged.
    await page.getByRole("link", { name: /^Providers/ }).click();
    await page.getByRole("combobox", { name: "Provider" }).selectOption("ollama");

    let body: Record<string, unknown> | null = null;
    await page.route("**/api/v1/settings/test/*", (r) => {
      body = r.request().postDataJSON();
      return r.fulfill({ json: { ok: true, latency_ms: 5, detail: "ok", models: [] } });
    });

    await page.getByRole("button", { name: "Test connection & fetch models" }).click();
    await expect.poll(() => body).not.toBeNull();
    // The route wraps the staged keys in `{ values }` (see `testSettingsProbe`).
    expect(body).toEqual({
      values: {
        "core.llm.provider": "ollama",
        "core.llm.ollama.base_url": "http://10.0.0.9:11434",
      },
    });
  });

  test("export calls the export endpoint (no download assertion)", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    let exportRequested = false;
    await page.route("**/api/v1/settings/export", (r) => {
      exportRequested = true;
      return r.fulfill({
        status: 200,
        contentType: "text/plain",
        body: "CORE_NEGOTIATION_RETRY_DELAY=10\n",
      });
    });

    await page.getByRole("button", { name: "Export overrides", exact: true }).click();
    await expect.poll(() => exportRequested).toBe(true);
    await expect(page.getByText("Overrides downloaded as maljan-settings.env")).toBeVisible();
  });

  test("the search box narrows the visible rows", async ({ authenticatedPage: page }) => {
    await page.goto(NEGOTIATION_PATH);

    await page.getByLabel("Search settings").fill("openai");
    await page.waitForURL(/\/settings\/configuration\/search\?q=openai/);
    await expect(page.getByText("OpenAI-compatible API key")).toBeVisible();
    await expect(page.getByText("Max iterations")).toHaveCount(0);
  });

  test("the search page lists a match under its group heading with an Open group link", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(`${SEARCH_PATH}?q=iterations`);

    await expect(page.getByRole("heading", { name: /Negotiation/ })).toBeVisible();
    await expect(page.getByRole("link", { name: "Open group" })).toBeVisible();
  });

  test("the search page shows a prompt instead of 'no match' when the query is cleared", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(`${SEARCH_PATH}?q=iterations`);
    await expect(page.getByRole("heading", { name: /Negotiation/ })).toBeVisible();

    await page.getByLabel("Search settings").fill("");
    await page.waitForURL(SEARCH_PATH);
    await expect(page.getByText("Type to search settings")).toBeVisible();
    await expect(page.getByText(/No settings match/)).toHaveCount(0);
  });

  test("a reset failure shows a dismissible banner and the console stays mounted", async ({
    authenticatedPage: page,
  }) => {
    const pageErrors: Error[] = [];
    page.on("pageerror", (err) => pageErrors.push(err));

    await page.goto(NEGOTIATION_PATH);

    // `core.negotiation.retry_delay` is the "ui"-sourced key in the mock —
    // one of the two negotiation entries that renders a "Remove override"
    // button to click (see the "per-row reset" test above).
    await page.route("**/api/v1/settings/core.negotiation.retry_delay", (r) =>
      r.request().method() === "DELETE"
        ? r.fulfill({ status: 500, json: { detail: "reset failed: database unavailable" } })
        : r.fallback()
    );

    const uiRow = page.locator("#setting-core\\.negotiation\\.retry_delay");
    await uiRow.getByRole("button", { name: "Remove override" }).click();

    const banner = page.getByRole("alert").filter({ hasText: "reset failed" });
    await expect(banner).toBeVisible();
    await expect(banner.getByRole("button", { name: "Dismiss error" })).toBeVisible();

    // The failure is scoped to the banner — the rest of the console,
    // including an unrelated row, is still on the page.
    await expect(page.locator("#settings-search")).toBeVisible();
    await expect(page.getByText("core.negotiation.max_iterations")).toBeVisible();

    await banner.getByRole("button", { name: "Dismiss error" }).click();
    await expect(page.getByRole("alert").filter({ hasText: "reset failed" })).toHaveCount(0);

    expect(pageErrors).toHaveLength(0);
  });

  test("clearing a required number field un-stages the edit instead of reverting it", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    const field = page.locator("#setting-core\\.negotiation\\.max_iterations input[type=number]");
    const pendingBar = page.getByTestId("changes-count");
    const requiredAlert = page.getByText(/Required — enter a value/);

    await field.fill("7");
    await expect(pendingBar).toHaveText("1 change");

    await field.fill("");
    await expect(requiredAlert).toBeVisible();
    await expect(pendingBar).toHaveCount(0);
    await expect(field).toHaveValue("");

    await field.fill("9");
    await expect(pendingBar).toHaveText("1 change");
    await expect(requiredAlert).toHaveCount(0);
  });

  test("typing into a list field entry by entry stages every entry, not just the first", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: { applied: ["core.negotiation.blocked_hosts"], applies: { next_job: 1 } },
        });
      }
      return r.fallback();
    });

    const field = page.locator("#setting-core\\.negotiation\\.blocked_hosts textarea");
    // Mirrors real typing, not a paste: fill the first entry, press Enter
    // (which used to be swallowed — see ListWidget's onChange), then type a
    // second entry at the cursor.
    await field.fill("a");
    await field.press("Enter");
    await field.type("b");

    await expect(field).toHaveValue("a\nb");
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");

    await page.getByRole("button", { name: "Review" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    await expect(page.getByText(/Applied 1 setting/)).toBeVisible();

    expect(patches).toEqual([
      { changes: { "core.negotiation.blocked_hosts": ["a", "b"] } },
    ]);
  });

  test("Discard resets the list widget's textarea back to the current value", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    const field = page.locator("#setting-core\\.negotiation\\.blocked_hosts textarea");
    await field.fill("a");
    await field.press("Enter");
    await field.type("b");
    await expect(field).toHaveValue("a\nb");
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");

    await page.getByRole("button", { name: "Discard", exact: true }).click();

    // The current value is the mock's `[]` default, so the textarea goes
    // back to empty rather than keeping the abandoned "a\nb" text.
    await expect(field).toHaveValue("");
    await expect(page.getByTestId("changes-count")).toHaveCount(0);
  });

  test("Only changed hides a default-sourced row and keeps a ui-sourced one", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    await page.getByRole("switch", { name: "Only changed" }).click();

    await expect(page.getByText("core.negotiation.retry_delay")).toBeVisible();
    await expect(page.getByText("core.negotiation.max_iterations")).toHaveCount(0);
  });

  test("the advanced fold is open by default when it holds a ui-sourced entry", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    const fold = page.locator('[data-testid^="advanced-"]');
    await expect(fold).toHaveJSProperty("open", true);
    await expect(page.getByText("core.negotiation.advanced_knob")).toBeVisible();
  });

  test("resetGroup unstages only that group's pending edits, leaving another group's edit intact", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);
    await expect(page.getByText("core.negotiation.max_iterations")).toBeVisible();

    // Stage an edit in "negotiation" (the group about to be reset)...
    const negotiationField = page.locator(
      "#setting-core\\.negotiation\\.max_iterations input[type=number]"
    );
    await negotiationField.fill("7");

    // ...and a second edit in "providers", a different group. A rail click,
    // not `page.goto` — this test depends on the negotiation edit above
    // surviving the switch.
    await page.getByRole("link", { name: /^Providers/ }).click();
    await page.getByRole("button", { name: "Set new value" }).click();
    await page.locator("input[type=password]").fill("sk-new-secret-value");
    await page.getByRole("button", { name: "Stage" }).click();
    await expect(page.getByTestId("changes-count")).toHaveText("2 changes");

    await page.route("**/api/v1/settings?**", (r) =>
      r.fulfill({
        json: { reset: ["core.negotiation.retry_delay", "core.negotiation.advanced_knob"] },
      })
    );

    // The rail link carries a pending marker once the group is dirty, so
    // match on the title prefix rather than the exact accessible name.
    await page.getByRole("link", { name: /^Negotiation/ }).click();
    await page.getByRole("button", { name: /Remove all overrides in this group/ }).click();
    await page.getByRole("button", { name: /Remove \d+ overrides/ }).click();

    // The negotiation group's own edit is gone, but the providers group's
    // staged secret survives — resetGroup must only touch its own group's
    // keys, not wipe `pending` wholesale.
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");
    await page.getByRole("link", { name: /^Providers/ }).click();
    await expect(page.getByText("new value staged")).toBeVisible();
  });

  /* B3 (dev audit 2026-09-06): `stage()` always wrote the key, so setting a
   * select back to the value it started at left the row MODIFIED and the bar
   * counting a change that would have been a no-op — clearable only by
   * hunting for "Discard change". */
  test("returning a field to its saved value clears the pending change", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(STATIC_PATH);

    const row = page.locator("#setting-core\\.static\\.provider");
    await row.locator("select").selectOption("r2");
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");
    await expect(row.getByText("modified")).toBeVisible();

    await row.locator("select").selectOption("ghidra");
    await expect(page.getByTestId("changes-count")).toHaveCount(0);
    await expect(row.getByText("modified")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Discard", exact: true })).toHaveCount(0);
  });

  test("a secret is still staged when it is cleared back to nothing", async ({
    authenticatedPage: page,
  }) => {
    /* The saved value of a secret is `null` however it is set — the API never
     * returns one — so "clear this secret" stages a value that deep-equals
     * what is stored, and the rule above must not swallow it. */
    await page.goto(PROVIDERS_PATH);

    await page.getByRole("button", { name: "Clear" }).click();
    await expect(page.getByText("will be cleared")).toBeVisible();
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");
  });

  /* B7 (dev audit 2026-09-06): ~1050 controls on this tab had neither an `id`
   * nor a `name`, so the title beside each one was associated with it only by
   * the widget's own aria-label — nothing autofill or id-targeting tooling can
   * follow. */
  test("a field's title is a label for a control that has an id and a name", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);

    const field = page.locator("#setting-core\\.negotiation\\.max_iterations input[type=number]");
    await expect(field).toHaveAttribute("id", "setting-input-core.negotiation.max_iterations");
    await expect(field).toHaveAttribute("name", "core.negotiation.max_iterations");

    // Clicking the title focuses the control, which is what the association is
    // for and what an aria-label alone never gave.
    await page.locator("#setting-label-core\\.negotiation\\.max_iterations").click();
    await expect(field).toBeFocused();
  });

  test("switching the sandbox provider reveals the Triage fields and hides the CAPE ones", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(SANDBOX_PATH);

    await expect(page.getByText("core.sandbox.cape2.base_url")).toBeVisible();
    await expect(page.getByText("core.sandbox.triage.base_url")).toHaveCount(0);

    await page
      .locator("#setting-core\\.sandbox\\.provider select")
      .selectOption("triage");

    await expect(page.getByText("core.sandbox.triage.base_url")).toBeVisible();
    await expect(page.getByText("core.sandbox.cape2.base_url")).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Test Triage connection" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Test CAPE connection" })).toHaveCount(0);
  });

  test("an edit that a provider switch hides is still staged and is counted", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(SANDBOX_PATH);

    await page
      .locator("#setting-core\\.sandbox\\.cape2\\.base_url input[type=text]")
      .fill("http://cape.example:8000");
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");

    await page.locator("#setting-core\\.sandbox\\.provider select").selectOption("triage");

    await expect(page.getByText("core.sandbox.cape2.base_url")).toHaveCount(0);
    await expect(page.getByTestId("changes-count")).toHaveText("2 changes");
    await expect(page.getByText("1 hidden by the current provider selection")).toBeVisible();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: [], applies: { next_job: 2 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Review" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    expect(patches).toEqual([
      {
        changes: {
          "core.sandbox.cape2.base_url": "http://cape.example:8000",
          "core.sandbox.provider": "triage",
        },
      },
    ]);
  });
});

test.describe("Settings → Configuration (stale stored override)", () => {
  test.use({ mockOptions: { user: { ...MOCK_USER, role: "admin" } } });

  test("a 422 that blames an untouched key is named in the action banner", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(NEGOTIATION_PATH);
    await page.route("**/api/v1/settings", (r) =>
      r.request().method() === "PATCH"
        ? r.fulfill({
            status: 422,
            json: { errors: { "core.negotiation.retry_delay": "Input should be >= 1" } },
          })
        : r.fallback()
    );
    await page
      .locator("#setting-core\\.negotiation\\.max_iterations input[type=number]")
      .fill("7");
    await page.getByRole("button", { name: "Review" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    const banner = page.getByRole("alert").filter({ hasText: "no longer valid" });
    await expect(banner).toBeVisible();
    await expect(banner).toContainText("core.negotiation.retry_delay");
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");
  });
});

test.describe("Settings → Configuration (non-admin)", () => {
  test("the tab is disabled with 'Admin role required' and cannot be opened", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings/profile");

    const tab = page.getByText("Configuration", { exact: true });
    await expect(tab).toHaveAttribute("aria-disabled", "true");
    await expect(tab).toHaveAttribute("title", "Admin role required");
    await expect(page.locator("#settings-search")).toHaveCount(0);
  });
});
