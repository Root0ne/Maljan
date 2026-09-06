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

    // The per-agent LLM override lives on its own catalog leaf,
    // `core.llm.agents` (`dict[str, AgentLLMConfig]`, one JSON map staged as
    // a whole exactly like `core.mcp.servers`) — not inside the definitions
    // map — so typing a model here stages one further pending change.
    await clone.getByLabel("static_r2 llm model").fill("gpt-4o-mini");
    await expect(page.getByText("2 changes pending")).toBeVisible();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: {
            applied: ["core.agents.definitions", "core.llm.agents"],
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
        "core.llm.agents": Record<string, { provider: string; model: string }>;
      };
    };
    const sent = body.changes["core.agents.definitions"];
    expect(sent.static_r2.role).toBe("static");
    expect(sent.static_r2.static_provider).toBe("r2");
    // The source is sent back untouched: a clone must not edit what it copied.
    expect(sent.static.static_provider).toBeNull();
    expect(sent.static.prompt).toBeNull();
    // The typed model lands in the `core.llm.agents` map under the clone's
    // own key, not folded into the definitions map. A model-only edit fills
    // in the effective global provider (the fixture's `core.llm.provider`,
    // "openai") rather than staging an invalid `provider: ""`.
    expect(Object.keys(body.changes)).toContain("core.llm.agents");
    expect(body.changes["core.llm.agents"].static_r2).toEqual({
      provider: "openai",
      model: "gpt-4o-mini",
    });
  });

  test("a profile is built from enabled analysts, ordered, set active and applied", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await expect(page.locator('[data-profile="default"]').getByText("built in")).toBeVisible();
    await expect(
      page.locator('[data-profile="default"]').getByLabel("default label")
    ).toBeDisabled();

    await page.getByLabel("new profile name").fill("lean");
    await page.getByRole("button", { name: "Add profile" }).click();

    const lean = page.locator('[data-profile="lean"]');
    await lean.getByLabel("lean add analyst").selectOption("network");
    await lean.getByLabel("lean add analyst").selectOption("static");
    await expect(lean.getByText("1. network")).toBeVisible();
    await lean.getByLabel("lean move static up").click();
    await expect(lean.getByText("1. static")).toBeVisible();
    await lean.getByRole("button", { name: "Set active" }).click();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: {
            applied: ["core.agents.profiles", "core.agents.profile"],
            applies: { next_job: 2 },
          },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: {
        "core.agents.profiles": Record<string, { analysts: string[] }>;
        "core.agents.profile": string;
      };
    };
    expect(body.changes["core.agents.profiles"].lean.analysts).toEqual(["static", "network"]);
    expect(body.changes["core.agents.profile"]).toBe("lean");
    expect(body.changes["core.agents.profiles"].default.analysts).toEqual([
      "static", "dynamic", "network",
    ]);
  });

  test("a generic analyst is created with a prompt and one server tool", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await page.getByLabel("new agent name").fill("strings");
    await page.getByRole("button", { name: "Add agent" }).click();

    const card = page.locator('[data-agent="strings"]');
    await expect(card).toBeVisible();
    await card.getByLabel("strings label").fill("Strings reviewer");
    await card.getByLabel("strings prompt").fill("Review the extracted strings for IOCs.");
    await card.getByRole("button", { name: "List tools" }).first().click();
    await card.getByLabel("strings tool network.extract_dns").check();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({
          json: { applied: ["core.agents.definitions"], applies: { next_job: 1 } },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, {
        role: string; prompt: string; tools: { kind: string; server: string; name: string }[];
      }>>;
    };
    const sent = body.changes["core.agents.definitions"].strings;
    expect(sent.role).toBe("generic");
    expect(sent.prompt).toBe("Review the extracted strings for IOCs.");
    expect(sent.tools).toEqual([{ kind: "mcp", server: "network", name: "extract_dns" }]);
  });

  test("a generic analyst can be given its static provider's tools", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await page.getByLabel("new agent name").fill("decomp");
    await page.getByRole("button", { name: "Add agent" }).click();
    const card = page.locator('[data-agent="decomp"]');
    await card.getByLabel("decomp prompt").fill("Read the decompiled code.");
    await card.getByLabel("decomp static provider").selectOption("r2");
    await card.getByLabel("decomp provider tools").check();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: [], applies: {} } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, {
        static_provider: string; tools: { kind: string }[];
      }>>;
    };
    const sent = body.changes["core.agents.definitions"].decomp;
    expect(sent.static_provider).toBe("r2");
    expect(sent.tools).toEqual([{ kind: "provider", server: null, name: null }]);
  });

  test("Resolve reports the prompt size and the tools without starting a job", async ({
    authenticatedPage: page,
  }) => {
    const jobPosts: unknown[] = [];
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") jobPosts.push(r.request().postDataJSON());
      return r.fallback();
    });

    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    const card = page.locator('[data-agent="network"]');
    await card.getByRole("button", { name: "Resolve" }).click();
    await expect(card.getByText("2 tools: extract_dns, read_pcap_summary")).toBeVisible();
    await expect(card.getByText("prompt 412 chars")).toBeVisible();
    expect(jobPosts).toHaveLength(0);
  });

  /* B6 (dev audit 2026-09-06): a resolved prompt and tool list described the
   * definition as it stood when Resolve was pressed, and stayed on screen
   * while that definition was edited underneath it. */
  test("editing what Resolve reads clears that card's result", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await page.getByLabel("new agent name").fill("strings");
    await page.getByRole("button", { name: "Add agent" }).click();
    const card = page.locator('[data-agent="strings"]');
    await card.getByRole("button", { name: "Resolve" }).click();
    await expect(card.getByText("prompt 412 chars")).toBeVisible();

    // The label changes nothing resolution reads; the prompt does.
    await card.getByLabel("strings label").fill("Strings reviewer");
    await expect(card.getByText("prompt 412 chars")).toBeVisible();

    await card.getByLabel("strings prompt").fill("Review the extracted strings.");
    await expect(card.getByText("prompt 412 chars")).toHaveCount(0);
  });

  test("a built-in definition offers only its enabled switch", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    const card = page.locator('[data-agent="dynamic"]');
    await expect(card.getByLabel("dynamic label")).toBeDisabled();
    await expect(card.getByLabel("dynamic prompt")).toBeDisabled();
    await expect(card.getByLabel("dynamic enabled")).toBeEnabled();
    await expect(card.getByRole("button", { name: "Remove" })).toHaveCount(0);

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: [], applies: {} } });
      }
      return r.fallback();
    });
    await card.getByLabel("dynamic enabled").uncheck();
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, { enabled: boolean; prompt: string | null }>>;
    };
    const sent = body.changes["core.agents.definitions"].dynamic;
    expect(sent.enabled).toBe(false);
    expect(sent.prompt).toBeNull();
  });

  test("the judge card offers no Clone, because the judge cannot be cloned", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    const judge = page.locator('[data-agent="judge"]');
    await expect(judge).toBeVisible();
    await expect(judge.getByRole("button", { name: "Clone" })).toHaveCount(0);
    await expect(
      page.locator('[data-agent="static"]').getByRole("button", { name: "Clone" })
    ).toHaveCount(1);
  });

  /* B5 (dev audit 2026-09-06): Clone with an empty name box did nothing at all
   * — no card, no message, no request — and an invalid name put its message
   * beside the name box at the bottom of the editor, nowhere near the button
   * that had just been pressed. */
  test("Clone with an empty name box names the copy after its source", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    const source = page.locator('[data-agent="static"]');
    await source.getByRole("button", { name: "Clone" }).click();
    await expect(page.locator('[data-agent="static_copy"]')).toBeVisible();

    // A second clone of the same source does not collide with the first.
    await source.getByRole("button", { name: "Clone" }).click();
    await expect(page.locator('[data-agent="static_copy2"]')).toBeVisible();

    const profile = page.locator('[data-profile="default"]');
    await profile.getByRole("button", { name: "Clone" }).click();
    await expect(page.locator('[data-profile="default_copy"]')).toBeVisible();
  });

  test("an invalid name is reported at the button that was pressed", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await page.getByLabel("new agent name").fill("Bad Name!");
    const source = page.locator('[data-agent="static"]');
    await source.getByRole("button", { name: "Clone" }).click();

    // On the card, not at the bottom of the editor.
    await expect(source.getByRole("alert")).toContainText("lowercase, starts with a letter");
    await expect(page.getByLabel("new agent name")).toBeFocused();
    await expect(page.locator('[data-agent="Bad Name!"]')).toHaveCount(0);

    await page.getByRole("button", { name: "Add agent" }).click();
    await expect(
      page.locator('[data-testid="agent-definitions-editor"] > p[role="alert"]')
    ).toContainText("lowercase, starts with a letter");
  });

  test("a validation error lands on the card that caused it", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await page.getByLabel("new agent name").fill("nameless");
    await page.getByRole("button", { name: "Add agent" }).click();

    // 422 body shape per `app.api.v1.settings`: a top-level `errors` map
    // keyed by dotted path (`tests/api/test_settings_routes.py`), not
    // wrapped in a `detail` envelope — `api.patchSettings` reads `body.errors`.
    // Since B2 the agent maps qualify that path with their own leaf, exactly
    // as the server map always did.
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        return r.fulfill({
          status: 422,
          json: {
            errors: { "core.agents.definitions.nameless.prompt": "a generic agent needs a prompt" },
          },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();
    await expect(
      page.locator('[data-agent="nameless"]').getByRole("alert")
    ).toContainText("a generic agent needs a prompt");
    // Not the leaf-wide "stored override" banner: this key belongs to a leaf
    // the operator just edited.
    await expect(page.getByText(/Stored override/)).toHaveCount(0);
  });

  /* B2 (dev audit 2026-09-06): an agent-map error can also name the whole
   * entry rather than one of its fields, and the profile map speaks the same
   * shape. Both used to arrive relative (`nameless`), match no card, and show
   * the generic stored-override banner. */
  test("an entry-level error lands on its card, for definitions and profiles", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Agents", exact: true }).click();

    await page.getByLabel("new agent name").fill("nameless");
    await page.getByRole("button", { name: "Add agent" }).click();
    await page.getByLabel("new profile name").fill("lean");
    await page.getByRole("button", { name: "Add profile" }).click();

    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        return r.fulfill({
          status: 422,
          json: {
            errors: {
              "core.agents.definitions.nameless": "an agent entry must be an object",
              "core.agents.profiles.lean": "a profile entry must be an object",
            },
          },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    await expect(
      page.locator('[data-agent="nameless"]').getByRole("alert")
    ).toContainText("an agent entry must be an object");
    await expect(
      page.locator('[data-profile="lean"]').getByText("a profile entry must be an object")
    ).toBeVisible();
    // The message belongs to one card, not to every card in the editor.
    await expect(
      page.locator('[data-agent="static"]').getByRole("alert")
    ).toHaveCount(0);
    await expect(page.getByText(/Stored override/)).toHaveCount(0);
  });
});
