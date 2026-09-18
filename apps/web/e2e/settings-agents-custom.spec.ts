import { expect, test } from "./fixtures";
import { MOCK_USER, MOCK_SETTINGS_VALUES } from "./mocks";

/**
 * A custom agent survives an apply and a reload, and deleting it survives one
 * too.
 *
 * This is the walk the console audit made by hand and could not finish: adding
 * "ahmet" flagged the four built-ins the operator had not touched as invalid,
 * kept printing "a generic agent needs a prompt" under a prompt that was
 * filled in, and persisted nothing. The three causes are in
 * `configuration/agentStaging.ts` (a built-in is staged as its role and its
 * switch, not whole), `useSettings.withoutErrorsFor` (an edit clears the
 * messages nested under its leaf, not only the leaf's own) and `ChangesBar`
 * (the count is of fields, not of rows).
 *
 * The store is mocked, so "reload" here is a `page.goto` against a values
 * fixture the PATCH has updated — the same thing the browser does, without a
 * backend.
 */

const AGENTS_PATH = "/settings/configuration/agents/agents";
const DEFINITIONS = "core.agents.definitions";

type DefinitionMap = Record<string, Record<string, unknown>>;

/** The values payload with this spec's own definition map in it. */
function storeWith(definitions: DefinitionMap) {
  const { values } = structuredClone(MOCK_SETTINGS_VALUES);
  return {
    values: {
      ...values,
      [DEFINITIONS]: { ...values[DEFINITIONS], value: definitions, source: "ui" },
    },
  };
}

test.describe("a custom agent", () => {
  test.use({ mockOptions: { user: { ...MOCK_USER, role: "admin" } } });

  test("is added, applied, re-read, deleted and gone", async ({ authenticatedPage: page }) => {
    // The store the mocked API answers with, which the PATCH below updates the
    // way the real settings service would.
    let stored = structuredClone(
      MOCK_SETTINGS_VALUES.values[DEFINITIONS].value,
    ) as DefinitionMap;
    const seeds = { ...stored };
    const patches: Record<string, DefinitionMap>[] = [];

    await page.route("**/api/v1/settings", async (route) => {
      if (route.request().method() === "PATCH") {
        const body = route.request().postDataJSON() as {
          changes: Record<string, DefinitionMap>;
        };
        patches.push(body.changes);
        const sent = body.changes[DEFINITIONS] ?? {};
        // A built-in the body narrows or leaves out is re-seeded, which is what
        // `agent_map.validate_definitions` does on the way in.
        const next: DefinitionMap = {};
        for (const [key, entry] of Object.entries(sent)) {
          next[key] = seeds[key] ? { ...seeds[key], ...entry } : entry;
        }
        for (const [key, seed] of Object.entries(seeds)) {
          if (!(key in next)) next[key] = seed;
        }
        stored = next;
        return route.fulfill({
          json: { applied: [DEFINITIONS], applies: { next_job: 1 } },
        });
      }
      return route.fulfill({ json: storeWith(stored) });
    });

    await page.goto(AGENTS_PATH);

    await page.getByLabel("new agent name").fill("ahmet");
    await page.getByRole("button", { name: "Add agent" }).click();

    const detail = page.locator('[data-agent-detail="ahmet"]');
    await detail.getByLabel("ahmet label").fill("Ahmet");
    await detail
      .getByLabel("ahmet prompt")
      .fill("Temporary audit agent. Summarise the sample in one sentence.");

    // No built-in the operator never touched is marked invalid by a new row.
    for (const key of ["judge", "static", "dynamic", "network"]) {
      await expect(page.locator(`[data-agent="${key}"]`).getByLabel("invalid")).toHaveCount(0);
    }

    await page.getByRole("button", { name: "Review" }).click();

    // What the panel says it is about to do. Comparing the stored map against
    // the narrowed staged one used to report all five built-ins as having
    // their prompts, tools and labels rewritten.
    const review = page.getByRole("dialog", { name: "Review changes" });
    await expect(review).toContainText("ahmet: added");
    await expect(review).toContainText("1 agent changed");
    for (const key of ["judge", "static", "dynamic", "network"]) {
      await expect(review).not.toContainText(`${key}: changed`);
    }

    await page.getByRole("button", { name: "Confirm and apply" }).click();

    // The status the apply leaves behind, which is the console saying the
    // PATCH was accepted. Waiting on this rather than on the bar disappearing
    // keeps the test off the six-second window the status line lingers for.
    await expect(page.getByRole("status").first()).toBeVisible();
    const sent = patches[0][DEFINITIONS] as DefinitionMap;
    expect(sent.ahmet).toMatchObject({ role: "generic", label: "Ahmet" });
    expect(sent.judge).toEqual({ role: "judge", enabled: true });

    await page.goto(AGENTS_PATH);
    const row = page.locator('[data-agent="ahmet"]');
    await expect(row).toBeVisible();
    await expect(row.getByText("Ahmet")).toBeVisible();

    await row.click();
    await page.locator('[data-agent-detail="ahmet"]').getByRole("button", { name: "Remove" }).click();
    await page.getByRole("button", { name: "Review" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    await expect(page.getByRole("status").first()).toBeVisible();

    await page.goto(AGENTS_PATH);
    await expect(page.locator('[data-agent="ahmet"]')).toHaveCount(0);
    await expect(page.locator('[data-agent="judge"]')).toBeVisible();
  });

  test("names every field the server refused, and clears each one as it is fixed", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(AGENTS_PATH);

    await page.getByLabel("new agent name").fill("ahmet");
    await page.getByRole("button", { name: "Add agent" }).click();

    await page.route("**/api/v1/settings", (route) => {
      if (route.request().method() !== "PATCH") return route.fallback();
      return route.fulfill({
        status: 422,
        json: {
          errors: {
            [`${DEFINITIONS}.ahmet.prompt`]: "a generic agent needs a prompt",
            [`${DEFINITIONS}.ahmet.label`]: "a generic agent needs a label",
          },
        },
      });
    });
    await page.getByRole("button", { name: "Review" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    // Two messages, counted as two — not "1 field needs attention" over a
    // semicolon-joined run-on sentence — and announced with the fields they
    // name rather than with the count alone.
    await expect(page.getByText("2 fields need attention").first()).toBeVisible();
    const announced = page.getByRole("status").first();
    await expect(announced).toContainText("a generic agent needs a prompt");
    await expect(announced).toContainText("a generic agent needs a label");

    const detail = page.locator('[data-agent-detail="ahmet"]');
    await expect(detail.getByText("a generic agent needs a prompt")).toBeVisible();

    // Validation re-runs on the edit: filling the prompt in takes the message
    // about it away rather than leaving it under a field that now has one.
    await detail.getByLabel("ahmet prompt").fill("Summarise the sample.");
    await expect(detail.getByText("a generic agent needs a prompt")).toHaveCount(0);
    await expect(detail.getByText("a generic agent needs a label")).toHaveCount(0);
  });
});
