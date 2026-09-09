import { test, expect } from "./fixtures";
import { MOCK_SETTINGS_SCHEMA_FULL, MOCK_SETTINGS_VALUES_FULL, MOCK_USER } from "./mocks";

/**
 * The setup-guide hub and its seven guides under `/settings/setup`.
 *
 * Uses `MOCK_SETTINGS_SCHEMA_FULL` / `MOCK_SETTINGS_VALUES_FULL` (`mocks.ts`)
 * rather than the console spec's smaller fixture: the guides together touch
 * every group those constants cover. The fixture's `core.llm.provider`
 * starts on `openai` with no key stored — "Not configured" per `status.ts` —
 * so the LLM guide walkthrough below, which stages `ollama`, is a real
 * change `stage()` will actually keep (staging a value back to what is
 * already saved un-stages it instead — see `useSettings.ts`).
 *
 * Per Task 18's report ("Concerns for Task 19's spec"): guide `state` (which
 * server/agent is being built, whether Resolve succeeded) is per-mount, so a
 * spec below never reloads mid-guide.
 */

const guidePath = (id: string, step?: string) =>
  `/settings/setup/${id}${step ? `?step=${step}` : ""}`;

test.describe("Settings → Setup guides (admin)", () => {
  test.use({
    mockOptions: {
      user: { ...MOCK_USER, role: "admin" },
      settingsSchema: MOCK_SETTINGS_SCHEMA_FULL,
      settingsValues: MOCK_SETTINGS_VALUES_FULL,
    },
  });

  test("the hub shows seven cards with their current-state status lines", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings/setup");

    await expect(page.getByRole("heading", { name: "Setup guides" })).toBeVisible();
    await expect(page.getByRole("link", { name: "Start" })).toHaveCount(7);

    await expect(page.getByTestId("guide-status-llm")).toHaveText("Not configured");
    await expect(page.getByTestId("guide-status-static")).toHaveText("ghidra");
    await expect(page.getByTestId("guide-status-sandbox")).toHaveText("mock (built-in fixtures)");
    await expect(page.getByTestId("guide-status-tool-server")).toHaveText("1 server enabled");
    await expect(page.getByTestId("guide-status-agent")).toHaveText(
      "No custom analysts · active profile default"
    );
    await expect(page.getByTestId("guide-status-memory")).toHaveText("memory (in-process)");
    await expect(page.getByTestId("guide-status-enrichment")).toHaveText("Off");
  });

  test("the LLM guide walks provider → credentials → test → models → limits → review and applies exactly the staged keys", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(guidePath("llm"));

    // Step 1: provider.
    await page.getByRole("radio", { name: /^Ollama/ }).click();
    await page.getByRole("button", { name: "Continue" }).click();

    // Step 2: credentials.
    await expect(page.getByRole("heading", { name: "Credentials and endpoint" })).toBeVisible();
    await page.getByRole("textbox", { name: "Ollama base URL" }).fill("http://10.0.0.5:11434");
    await page.getByRole("button", { name: "Continue" }).click();

    // Step 3: test — blocked until the probe passes.
    await expect(page.getByRole("heading", { name: "Test the connection" })).toBeVisible();
    const continueButton = page.getByRole("button", { name: "Continue" });
    await expect(continueButton).toBeDisabled();
    await expect(page.getByText("run the connection test first")).toBeVisible();

    await page.route("**/api/v1/settings/test/llm", (route) =>
      route.fulfill({
        json: { ok: true, latency_ms: 120, detail: "ok", models: ["qwen3:8b", "qwen3:4b"], tools: null },
      })
    );
    await page.getByRole("button", { name: "Test connection & fetch models" }).click();
    await expect(page.getByText(/ok · 120 ms · ok/)).toBeVisible();
    await expect(continueButton).toBeEnabled();
    await continueButton.click();

    // Step 4: models — the datalist options came from the probe.
    await expect(page.getByRole("heading", { name: "Expert and judge models" })).toBeVisible();
    await expect(
      page.locator('[id="models-core.llm.ollama.expert_model"] option[value="qwen3:8b"]')
    ).toHaveCount(1);
    await expect(
      page.locator('[id="models-core.llm.ollama.judge_model"] option[value="qwen3:4b"]')
    ).toHaveCount(1);
    await page.getByRole("combobox", { name: "Ollama expert model" }).fill("qwen3:8b");
    await page.getByRole("combobox", { name: "Ollama judge model" }).fill("qwen3:4b");
    await page.getByRole("button", { name: "Continue" }).click();

    // Step 5: limits — defaults are fine, no edit needed.
    await expect(page.getByRole("heading", { name: "Limits" })).toBeVisible();
    await page.getByRole("button", { name: "Continue" }).click();

    // Step 6: review and apply.
    await expect(page.getByRole("heading", { name: "Review and apply" })).toBeVisible();

    const patches: Record<string, unknown>[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON() as Record<string, unknown>);
        return r.fulfill({
          json: {
            applied: [
              "core.llm.provider",
              "core.llm.ollama.base_url",
              "core.llm.ollama.expert_model",
              "core.llm.ollama.judge_model",
            ],
            applies: { next_job: 4 },
          },
        });
      }
      return r.fallback();
    });

    await page.getByRole("button", { name: "Apply", exact: true }).click();
    await expect(page.getByText("Applied 4 settings · 4 on the next analysis")).toBeVisible();

    expect(patches).toHaveLength(1);
    expect(Object.keys(patches[0].changes as Record<string, unknown>).sort()).toEqual(
      [
        "core.llm.ollama.base_url",
        "core.llm.ollama.expert_model",
        "core.llm.ollama.judge_model",
        "core.llm.provider",
      ].sort()
    );
    expect(patches[0].changes).toEqual({
      "core.llm.provider": "ollama",
      "core.llm.ollama.base_url": "http://10.0.0.5:11434",
      "core.llm.ollama.expert_model": "qwen3:8b",
      "core.llm.ollama.judge_model": "qwen3:4b",
    });
  });

  test("the static guide with r2 sends the provider and its binary path", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(guidePath("static"));

    await page.getByRole("radio", { name: /^radare2 MCP/ }).click();
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByRole("heading", { name: "Settings for this analyser" })).toBeVisible();
    await page.getByRole("textbox", { name: "radare2 binary path" }).fill("/usr/bin/r2");
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByRole("heading", { name: "Test the analyser" })).toBeVisible();
    await page.route("**/api/v1/settings/test/r2", (route) =>
      route.fulfill({ json: { ok: true, latency_ms: 30, detail: "radare2 2 files", models: null, tools: null } })
    );
    await page.getByRole("button", { name: "Test radare2 MCP" }).click();
    await expect(page.getByText(/ok · 30 ms/)).toBeVisible();
    await page.getByRole("button", { name: "Continue" }).click();

    const patches: Record<string, unknown>[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON() as Record<string, unknown>);
        return r.fulfill({
          json: { applied: ["core.static.provider", "core.static.r2.binary_path"], applies: { next_job: 2 } },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply", exact: true }).click();
    await expect(page.getByText(/Applied 2 settings/)).toBeVisible();

    expect(patches).toEqual([
      {
        changes: {
          "core.static.provider": "r2",
          "core.static.r2.binary_path": "/usr/bin/r2",
        },
      },
    ]);
  });

  test("the tool-server guide creates a new server and leaves the built-in one untouched", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(guidePath("tool-server"));

    await expect(page.getByRole("heading", { name: "Which server" })).toBeVisible();
    await page.getByLabel("new server name").fill("r2custom");
    await page.getByRole("button", { name: "Use this server" }).click();
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByRole("heading", { name: "Transport and connection" })).toBeVisible();
    await page.getByRole("textbox", { name: "r2custom command" }).fill("r2custom-mcp-server");
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByRole("heading", { name: "Tools" })).toBeVisible();
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByRole("heading", { name: "Analysts" })).toBeVisible();
    await page.getByRole("checkbox", { name: "r2custom agent static" }).check();
    await page.getByRole("button", { name: "Continue" }).click();

    const patches: Record<string, unknown>[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON() as Record<string, unknown>);
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply", exact: true }).click();
    await expect(page.getByText(/Applied 1 setting/)).toBeVisible();

    expect(patches).toHaveLength(1);
    const servers = (patches[0].changes as Record<string, unknown>)["core.mcp.servers"] as Record<
      string,
      { transport: string; command: string; agents: string[] }
    >;
    expect(servers.r2custom).toMatchObject({
      transport: "stdio",
      command: "r2custom-mcp-server",
      agents: ["static"],
    });
    const originalServers = MOCK_SETTINGS_VALUES_FULL.values["core.mcp.servers"].value as Record<
      string,
      unknown
    >;
    expect(servers.network).toEqual(originalServers.network);
  });

  test("the agent guide clones static, adds it to a new profile and activates it", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(guidePath("agent"));

    // Step: start from.
    await expect(page.getByRole("heading", { name: "Start from" })).toBeVisible();
    await page.getByRole("radio", { name: "Clone a built-in" }).click();
    await page.getByLabel("new agent name").fill("static_r2");
    await page.getByRole("button", { name: "Create the analyst" }).click();
    await page.getByRole("button", { name: "Continue" }).click();

    // Step: prompt — left empty.
    await expect(page.getByRole("heading", { name: "Prompt" })).toBeVisible();
    await page.getByRole("button", { name: "Continue" }).click();

    // Step: tools.
    await expect(page.getByRole("heading", { name: "Tools" })).toBeVisible();
    await page.getByRole("checkbox", { name: "static_r2 server network" }).check();
    await page.getByRole("button", { name: "Continue" }).click();

    // Step: model — left empty.
    await expect(page.getByRole("heading", { name: "Model" })).toBeVisible();
    await page.getByRole("button", { name: "Continue" }).click();

    // Step: resolve — blocked until it succeeds.
    await expect(page.getByRole("heading", { name: "Resolve" })).toBeVisible();
    const continueButton = page.getByRole("button", { name: "Continue" });
    await expect(continueButton).toBeDisabled();
    await expect(page.getByText("run Resolve first")).toBeVisible();

    await page.route("**/api/v1/settings/test/agent?**", (route) =>
      route.fulfill({
        json: {
          ok: true,
          latency_ms: 80,
          detail: "2 tools",
          models: null,
          tools: null,
          details: {
            prompt_chars: 1200,
            prompt_sha256: "x",
            prompt: "…",
            llm: { provider: "ollama", model: "qwen3:8b" },
            static_provider: "r2",
            servers: [],
          },
        },
      })
    );
    await page.getByRole("button", { name: "Resolve", exact: true }).click();
    await expect(page.getByText(/ok · 80 ms · 2 tools/)).toBeVisible();
    await expect(continueButton).toBeEnabled();
    await continueButton.click();

    // Step: add to a profile.
    await expect(page.getByRole("heading", { name: "Add to a profile" })).toBeVisible();
    await page.getByRole("radio", { name: /Create a new profile from default/ }).click();
    await page.getByLabel("new profile name").fill("full");
    await page.getByRole("checkbox", { name: "Make it the active profile" }).check();
    await page.getByRole("button", { name: "Continue" }).click();

    const patches: Record<string, unknown>[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON() as Record<string, unknown>);
        return r.fulfill({
          json: {
            applied: ["core.agents.definitions", "core.agents.profiles", "core.agents.profile"],
            applies: { next_job: 3 },
          },
        });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply", exact: true }).click();
    await expect(page.getByText(/Applied 3 settings/)).toBeVisible();

    expect(patches).toHaveLength(1);
    const changes = patches[0].changes as Record<string, unknown>;
    const definitions = changes["core.agents.definitions"] as Record<
      string,
      { role: string; label: string }
    >;
    expect(definitions.static_r2).toMatchObject({ role: "static", label: "Static analyst (copy)" });

    const profiles = changes["core.agents.profiles"] as Record<string, { analysts: string[] }>;
    expect(profiles.full.analysts.at(-1)).toBe("static_r2");

    expect(changes["core.agents.profile"]).toBe("full");
  });

  /* Task 21: the review step listed only this guide's own keys, but Apply
   * PATCHes the whole pending map — anything staged in the console before the
   * guide was opened went out unannounced. */
  test("the review names a key staged in the console and sends it with the guide's own", async ({
    authenticatedPage: page,
  }) => {
    // Stage a console key first. Every step from here is a client-side
    // navigation: a `page.goto` would remount the provider and drop it.
    await page.goto("/settings/configuration/tools/memory");
    await page.locator("#setting-core\\.memory\\.top_k input[type=number]").fill("9");
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");

    await page.getByRole("link", { name: "Setup guides" }).click();
    await page.getByRole("link", { name: "Start" }).first().click();
    await page.waitForURL("**/settings/setup/llm");

    await page.getByRole("radio", { name: /^Ollama/ }).click();
    await page.getByRole("button", { name: /Review and apply/ }).click();

    await expect(page.getByText("Also staged elsewhere")).toBeVisible();
    await expect(page.getByText("Neighbours per lookup")).toBeVisible();
    await expect(page.getByText("Apply also sends the 1 change staged elsewhere.")).toBeVisible();

    const patches: Record<string, unknown>[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON() as Record<string, unknown>);
        return r.fulfill({
          json: {
            applied: ["core.llm.provider", "core.memory.top_k"],
            applies: { next_job: 2 },
          },
        });
      }
      return r.fallback();
    });

    await page.getByRole("button", { name: "Apply", exact: true }).click();
    await expect(page.getByText(/Applied 2 settings/)).toBeVisible();
    expect(patches).toEqual([
      { changes: { "core.llm.provider": "ollama", "core.memory.top_k": 9 } },
    ]);
  });

  test("leaving the LLM guide after staging shows the rail badge and the changes bar", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(guidePath("llm"));

    await page.getByRole("radio", { name: /^Ollama/ }).click();
    await page.getByRole("link", { name: "Open in the full settings" }).first().click();
    await page.waitForURL("**/settings/configuration/models/llm");

    const link = page.getByRole("link", { name: /^LLM & model/ });
    await expect(link).toHaveAccessibleName(/1 unsaved changes/);
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");
  });
});

test.describe("Settings → Setup guides (LLM unconfigured redirects to the hub)", () => {
  test.use({
    mockOptions: {
      user: { ...MOCK_USER, role: "admin" },
      settingsSchema: MOCK_SETTINGS_SCHEMA_FULL,
      settingsValues: MOCK_SETTINGS_VALUES_FULL,
    },
  });

  test("/settings/configuration lands on the setup hub", async ({ authenticatedPage: page }) => {
    await page.goto("/settings/configuration");
    await page.waitForURL("**/settings/setup");
    await expect(page.getByRole("heading", { name: "Setup guides" })).toBeVisible();
  });
});

test.describe("Settings → Setup guides (LLM configured redirects to the console)", () => {
  const configuredValues = structuredClone(MOCK_SETTINGS_VALUES_FULL);
  configuredValues.values["core.llm.provider"] = {
    ...configuredValues.values["core.llm.provider"],
    value: "ollama",
  };
  configuredValues.values["core.llm.ollama.base_url"] = {
    ...configuredValues.values["core.llm.ollama.base_url"],
    value: "http://localhost:11434",
  };

  test.use({
    mockOptions: {
      user: { ...MOCK_USER, role: "admin" },
      settingsSchema: MOCK_SETTINGS_SCHEMA_FULL,
      settingsValues: configuredValues,
    },
  });

  test("/settings/configuration lands on the first group", async ({ authenticatedPage: page }) => {
    await page.goto("/settings/configuration");
    await page.waitForURL("**/settings/configuration/models/llm");
    await expect(page.getByRole("heading", { name: "LLM & model", level: 2 })).toBeVisible();
  });
});
