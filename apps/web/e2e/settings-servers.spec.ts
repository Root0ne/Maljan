import { expect, test } from "./fixtures";
import { MOCK_USER } from "./mocks";

/**
 * The tool-server map and the REST sandbox editor, end to end.
 *
 * Both live under the admin-only Configuration tab, so every test here
 * overrides `mockOptions.user` to `role: "admin"` the way
 * `settings-configuration.spec.ts` does. Fixture data (`e2e/mocks.ts`): the
 * `mcp` group carries two built-ins — `network` (a custom transport with no
 * token set) and `threatintel` (a token sourced from `.env`) — and the
 * `sandbox` group now also carries the four `core.sandbox.rest.*` leaves the
 * REST editor renders, plus the `sandbox-rest/preview` route.
 */

test.describe("tool servers and the REST sandbox", () => {
  test.use({ mockOptions: { user: { ...MOCK_USER, role: "admin" } } });

  test("a new server is added, probed, narrowed to two tools and bound to static", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Tool servers (MCP)", exact: true }).click();

    await page.getByLabel("new server name").fill("r2custom");
    await page.getByRole("button", { name: "Add server" }).click();
    const card = page.locator('[data-server="r2custom"]');
    await expect(card).toBeVisible();

    await card.getByLabel("r2custom command").fill("r2mcp");
    await card.getByRole("button", { name: "Test" }).click();
    await expect(card.getByText("3 tools: open_file, analyze, list_imports")).toBeVisible();

    // A new server starts with no tools allowed at all: tick the two it
    // should keep, and leave the third unticked.
    await card.getByLabel("r2custom tool open_file").check();
    await card.getByLabel("r2custom tool analyze").check();
    await card.getByLabel("r2custom agent static").check();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as { changes: Record<string, Record<string, {
      enabled: boolean; transport: string; tools: string[]; agents: string[]; command: string }>> };
    const sent = body.changes["core.mcp.servers"].r2custom;
    expect(sent.enabled).toBe(true);
    expect(sent.transport).toBe("stdio");
    expect(sent.command).toBe("r2mcp");
    expect(sent.tools).toEqual(["open_file", "analyze"]);
    expect(sent.agents).toEqual(["static"]);
  });

  test("a built-in offers disable rather than remove, and one PATCH disables it while its key and other fields survive", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Tool servers (MCP)", exact: true }).click();

    const intel = page.locator('[data-server="threatintel"]');
    await expect(intel.getByRole("button", { name: "Disable" })).toBeVisible();
    await expect(intel.getByRole("button", { name: "Remove" })).toHaveCount(0);

    await intel.getByRole("button", { name: "Disable" }).click();
    await expect(intel).toBeVisible();
    await expect(intel.getByLabel("threatintel enabled")).not.toBeChecked();
    await expect(page.getByText("1 change pending")).toBeVisible();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, {
        enabled: boolean; command: string; args: string[]; agents: string[]; tools: string[] | null;
      }>>;
    };
    // Disabling stages the whole map, not a per-server diff, so the built-in
    // key stays present with everything but `enabled` unchanged from the
    // fixture — a disabled server is still a configured one.
    const sent = body.changes["core.mcp.servers"].threatintel;
    expect(sent.enabled).toBe(false);
    expect(sent.command).toBe("python");
    expect(sent.args).toEqual(["threatintel-mcp/server.py"]);
    expect(sent.agents).toEqual(["judge"]);
    expect(sent.tools).toBeNull();
  });

  test("a token is typed once, never read back, and an untouched one stays untouched", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Tool servers (MCP)", exact: true }).click();

    // The fixture's `threatintel` entry arrives with a token set in .env: the
    // page may say so, but must never carry the value.
    const intel = page.locator('[data-server="threatintel"]');
    await intel.getByLabel("threatintel transport").selectOption("http");
    await expect(intel.locator('[data-token-state="threatintel"]')).toHaveText("set in .env");
    await expect(page.getByLabel("threatintel auth token")).toHaveCount(0);

    const custom = page.locator('[data-server="network"]');
    await custom.getByLabel("network transport").selectOption("http");
    await custom.getByRole("button", { name: "Replace token" }).click();
    await custom.getByLabel("network auth token").fill("s3cr3t");

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Apply" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, { auth_token: string }>>;
    };
    const sent = body.changes["core.mcp.servers"];
    expect(sent.network.auth_token).toBe("s3cr3t");
    // The card nobody edited sends the mask back, which the API reads as
    // "leave the stored row alone" — not as a token of ten asterisks.
    expect(sent.threatintel.auth_token).toBe("**********");

    // Nothing on the page renders the typed value after it is applied.
    await expect(page.getByText("s3cr3t")).toHaveCount(0);
  });

  test("the REST editor previews counts, a channel error, a truncation and the target hash", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Sandbox provider", exact: true }).click();

    await expect(page.getByTestId("rest-sandbox-editor")).toHaveCount(0);
    await page.locator("#setting-core\\.sandbox\\.provider select").selectOption("rest");
    const editor = page.getByTestId("rest-sandbox-editor");
    await expect(editor).toBeVisible();
    await expect(editor.getByRole("button", { name: "Preview mapping" })).toBeDisabled();

    await editor.getByLabel("Mapping: processes").fill("$.procs[*]");
    await page.getByLabel("Paste a sample response").fill('{"procs": [{"pid": 1}, {}]}');
    await editor.getByRole("button", { name: "Preview mapping" }).click();

    // `processes` comes back truncated at the server's row ceiling.
    await expect(editor.locator('[data-channel="processes"]')).toHaveText(
      "2 / 1 / 1 · truncated at 5000"
    );
    // `dns` comes back with a channel-local error instead of counts.
    await expect(editor.locator('[data-channel="dns"]')).toHaveText(
      "JSONPath syntax error at position 3"
    );
    // The target hash row shows the hash the mocked preview matched against.
    await expect(editor.locator('[data-channel="target_sha256"]')).toHaveText("ab");
    await expect(editor.getByText("sample hash: ab")).toBeVisible();
  });

  test("a mapping row is hidden when the report format is not generic", async ({
    authenticatedPage: page,
  }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Configuration" }).click();
    await page.getByRole("button", { name: "Sandbox provider", exact: true }).click();
    await page.locator("#setting-core\\.sandbox\\.provider select").selectOption("rest");

    await expect(page.getByLabel("Mapping: processes")).toBeVisible();
    await page.locator("#setting-core\\.sandbox\\.rest\\.report\\.format select").selectOption("cape2");
    await expect(page.getByLabel("Mapping: processes")).toHaveCount(0);
  });
});
