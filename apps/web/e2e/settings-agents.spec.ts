import { expect, test } from "./fixtures";
import { MOCK_USER } from "./mocks";

/**
 * Agent definitions and profiles, end to end.
 *
 * Both editors live under the admin-only Configuration tab, so every test
 * overrides `mockOptions.user` to `role: "admin"` the way
 * `settings-servers.spec.ts` does. Fixture data (`e2e/mocks.ts`): the `agents`
 * group carries the four built-in definitions, the `default` profile and the
 * agent probe route.
 */

test.describe("agent definitions and profiles", () => {
  test.use({ mockOptions: { user: { ...MOCK_USER, role: "admin" } } });

  test("cloning the static analyst stages a new definition on radare2", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    const source = page.locator('[data-agent="static"]');
    await expect(source).toBeVisible();
    await expect(source.getByText("built in", { exact: true })).toBeVisible();
    await expect(source.getByLabel("static prompt")).toBeDisabled();

    await page.getByLabel("new agent name").fill("static_r2");
    await source.getByRole("button", { name: "Clone" }).click();

    const clone = page.locator('[data-agent="static_r2"]');
    await expect(clone).toBeVisible();
    await expect(clone.getByLabel("static_r2 prompt")).toBeEnabled();
    await clone.getByLabel("static_r2 static provider").selectOption("r2");

    // The per-agent LLM override is a setting of its own
    // (`core.llm.agents.<key>.*`), staged alongside — not inside — the
    // definitions map, so it shows up as a second pending change.
    await clone.getByLabel("static_r2 llm model").fill("gpt-4o-mini");
    await expect(page.getByText("2 changes pending")).toBeVisible();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: {
            applied: ["core.agents.definitions", "core.llm.agents.static_r2.model"],
            applies: { next_job: 1 },
          },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, unknown> & {
        "core.agents.definitions": Record<
          string,
          { role: string; static_provider: string | null; prompt: string | null }
        >;
      };
    };
    const sent = body.changes["core.agents.definitions"];
    expect(sent.static_r2.role).toBe("static");
    expect(sent.static_r2.static_provider).toBe("r2");
    // The source is sent back untouched: a clone must not edit what it copied.
    expect(sent.static.static_provider).toBeNull();
    expect(sent.static.prompt).toBeNull();
    // The typed model is staged as its own leaf, not folded into the
    // definitions map.
    expect(Object.keys(body.changes)).toContain("core.llm.agents.static_r2.model");
    expect(body.changes["core.llm.agents.static_r2.model"]).toBe("gpt-4o-mini");
  });
});
