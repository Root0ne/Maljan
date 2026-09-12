import { expect, test } from "./fixtures";
import { MOCK_USER } from "./mocks";

/**
 * The tool-server map and the REST sandbox editor, end to end.
 *
 * Both live under the admin-only Configuration tab, so every test here
 * overrides `mockOptions.user` to `role: "admin"` the way
 * `settings-configuration.spec.ts` does. Fixture data (`e2e/mocks.ts`): the
 * `mcp` group carries two built-ins — `network` (a custom transport with no
 * token set) and `threatintel` (a token set from the UI) — and the
 * `sandbox` group now also carries the four `core.sandbox.rest.*` leaves the
 * REST editor renders, plus the `sandbox-rest/preview` route.
 *
 * `ServerMapEditor` is a master–detail editor (task 11): the left-hand list
 * (`[data-server="<key>"]`, `role="option"`) carries only the key, transport
 * and probe verdict, and every field lives in the selected server's detail
 * pane (`[data-server-detail="<key>"]`), so a test always clicks the row
 * before reaching into the detail. The apply flow itself has no "Apply"
 * button: staging shows the pending count on `data-testid="changes-count"`,
 * "Review" opens the confirmation panel, and "Confirm and apply" sends the
 * one PATCH.
 */

const MCP_PATH = "/settings/configuration/tools/mcp";
const SANDBOX_PATH = "/settings/configuration/tools/sandbox";

test.describe("tool servers and the REST sandbox", () => {
  test.use({ mockOptions: { user: { ...MOCK_USER, role: "admin" } } });

  test("a new server is added, probed, narrowed to two tools and bound to static", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(MCP_PATH);

    await page.getByLabel("new server name").fill("r2custom");
    await page.getByRole("button", { name: "Add server" }).click();
    const row = page.locator('[data-server="r2custom"]');
    await expect(row).toBeVisible();
    await row.click();

    const detail = page.locator('[data-server-detail="r2custom"]');
    await detail.getByLabel("r2custom command").fill("r2mcp");
    await detail.getByRole("button", { name: "Test" }).click();
    await expect(detail.getByText("3 tools: open_file, analyze, list_imports")).toBeVisible();

    // A new server starts with no tools allowed at all: tick the two it
    // should keep, and leave the third unticked.
    await detail.getByLabel("r2custom tool open_file").check();
    await detail.getByLabel("r2custom tool analyze").check();
    await detail.getByLabel("r2custom agent static").check();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Review" }).click();
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

  /* Task 14: selecting a server was never anything more than reading a
   * `<section>` that was always mounted, but the master–detail rewrite
   * (task 11) makes the detail pane conditional on which row is picked —
   * so an edit staged on one server must survive switching away and back,
   * not just staying stuck to whichever server happens to be selected. */
  test("selecting another server keeps the first one's staged edits", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(MCP_PATH);

    await page.locator('[data-server="network"]').click();
    const networkDetail = page.locator('[data-server-detail="network"]');
    await networkDetail.getByLabel("network label").fill("Network (staged)");
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");

    await page.locator('[data-server="threatintel"]').click();
    await expect(page.locator('[data-server-detail="threatintel"]')).toBeVisible();
    await expect(page.locator('[data-server-detail="network"]')).toHaveCount(0);

    await page.locator('[data-server="network"]').click();
    await expect(
      page.locator('[data-server-detail="network"]').getByLabel("network label")
    ).toHaveValue("Network (staged)");
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");
  });

  /* Task 14: a server with no probe result yet says so, with a way to get
   * one right there in the Tools section — distinct from the header's own
   * "Test" button, which the first test already exercises. */
  test("the Tools section says to run Test before a probe has been made", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(MCP_PATH);

    await page.getByLabel("new server name").fill("r2custom");
    await page.getByRole("button", { name: "Add server" }).click();
    const detail = page.locator('[data-server-detail="r2custom"]');
    await expect(detail.getByText("Run Test to load the tool list")).toBeVisible();

    await detail.getByRole("button", { name: "Load tool list" }).click();
    await expect(detail.getByText("3 tools: open_file, analyze, list_imports")).toBeVisible();
    await expect(detail.getByText("Run Test to load the tool list")).toHaveCount(0);
  });

  /* BUG 2 (live e2e 2026-09-07): `MCPServerConfig.env` had no control at all,
   * so a stdio server needing a fixed variable (Qu1cksc0pe wants
   * `SC0PE_MCP_TRANSPORT=stdio`) had to be wrapped in a shell script. */
  test("a fixed environment map is staged and sent with the server", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(MCP_PATH);

    await page.getByLabel("new server name").fill("qu1cksc0pe");
    await page.getByRole("button", { name: "Add server" }).click();
    const detail = page.locator('[data-server-detail="qu1cksc0pe"]');
    await detail.getByLabel("qu1cksc0pe command").fill("qu1cksc0pe.py");
    await detail.getByLabel("qu1cksc0pe env", { exact: true }).fill('{"SC0PE_MCP_TRANSPORT": "stdio"}');

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Review" }).click();
    await page.getByRole("button", { name: "Confirm and apply" }).click();

    const body = patches[0] as {
      changes: Record<string, Record<string, { env: Record<string, string> }>>;
    };
    expect(body.changes["core.mcp.servers"].qu1cksc0pe.env).toEqual({
      SC0PE_MCP_TRANSPORT: "stdio",
    });
  });

  /* B6 (dev audit 2026-09-06): a probe result outlived the configuration it
   * described — the green "3 tools: …" line stayed up while the command it had
   * dialled was edited out from under it. */
  test("editing what a probe dialled clears that card's result", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(MCP_PATH);

    await page.getByLabel("new server name").fill("r2custom");
    await page.getByRole("button", { name: "Add server" }).click();
    const detail = page.locator('[data-server-detail="r2custom"]');
    await detail.getByLabel("r2custom command").fill("r2mcp");
    await detail.getByRole("button", { name: "Test" }).click();
    await expect(detail.getByText("3 tools: open_file, analyze, list_imports")).toBeVisible();

    // The allow-list is rendered from that same result, so ticking a tool must
    // not clear it.
    await detail.getByLabel("r2custom tool open_file").check();
    await expect(detail.getByText("3 tools: open_file, analyze, list_imports")).toBeVisible();

    await detail.getByLabel("r2custom command").fill("something-else");
    await expect(detail.getByText("3 tools: open_file, analyze, list_imports")).toHaveCount(0);
  });

  test("a built-in offers disable rather than remove, and one PATCH disables it while its key and other fields survive", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(MCP_PATH);

    await page.locator('[data-server="threatintel"]').click();
    const detail = page.locator('[data-server-detail="threatintel"]');
    await expect(detail.getByRole("button", { name: "Disable" })).toBeVisible();
    await expect(detail.getByRole("button", { name: "Remove" })).toHaveCount(0);

    await detail.getByRole("button", { name: "Disable" }).click();
    await expect(detail.getByLabel("threatintel enabled")).not.toBeChecked();
    await expect(page.getByTestId("changes-count")).toHaveText("1 change");

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Review" }).click();
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
    expect(sent.args).toEqual(["services/threatintel-mcp/server.py"]);
    expect(sent.agents).toEqual(["judge"]);
    expect(sent.tools).toBeNull();
  });

  test("a token is typed once, never read back, and an untouched one stays untouched", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(MCP_PATH);

    // The fixture's `threatintel` entry arrives with a token set from the
    // UI: the page may say so, but must never carry the value.
    await page.locator('[data-server="threatintel"]').click();
    const intel = page.locator('[data-server-detail="threatintel"]');
    await intel.getByLabel("threatintel transport").selectOption("http");
    await expect(intel.locator('[data-token-state="threatintel"]')).toHaveText("set from the UI");
    await expect(page.getByLabel("threatintel auth token")).toHaveCount(0);

    await page.locator('[data-server="network"]').click();
    const custom = page.locator('[data-server-detail="network"]');
    await custom.getByLabel("network transport").selectOption("http");
    await custom.getByRole("button", { name: "Replace token" }).click();
    await custom.getByLabel("network auth token").fill("s3cr3t");
    // `SecretField` commits on its own "Stage" button, not on keystroke — the
    // typed value stages only once this is pressed (task 11 report).
    await custom.getByRole("button", { name: "Stage" }).click();

    const patches: unknown[] = [];
    await page.route("**/api/v1/settings", (r) => {
      if (r.request().method() === "PATCH") {
        patches.push(r.request().postDataJSON());
        return r.fulfill({ json: { applied: ["core.mcp.servers"], applies: { next_job: 1 } } });
      }
      return r.fallback();
    });
    await page.getByRole("button", { name: "Review" }).click();
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
    await page.goto(SANDBOX_PATH);

    await expect(page.getByTestId("rest-sandbox-editor")).toHaveCount(0);
    await page.locator("#setting-core\\.sandbox\\.provider select").selectOption("rest");
    const editor = page.getByTestId("rest-sandbox-editor");
    await expect(editor).toBeVisible();

    // The sample block sits behind a <summary> collapsed by default; its
    // contents are inert until the disclosure is opened.
    await editor.getByText("Test with a sample response").click();

    /* B8 (dev audit 2026-09-06): the button used to stay disabled until the
     * textarea had seen a keystroke, so a value that arrived any other way
     * left it dead with nothing saying why. It is live from the start and
     * names what is missing. */
    await expect(editor.getByRole("button", { name: "Preview mapping" })).toBeEnabled();
    await editor.getByRole("button", { name: "Preview mapping" }).click();
    await expect(editor.getByText("paste a sample response first")).toBeVisible();

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
    // WEB-1: that column counts rows for every other channel, and this row
    // does not select rows at all — the cell and the footnote both say so.
    await expect(editor.locator('[data-channel="target_sha256"]')).toHaveText("hash: ab");
    await expect(
      editor.getByText(/the target_sha256 row selects a single value/)
    ).toBeVisible();
    await expect(editor.getByText("sample hash: ab")).toBeVisible();
  });

  test("a mapping row is hidden when the report format is not generic", async ({
    authenticatedPage: page,
  }) => {
    await page.goto(SANDBOX_PATH);
    await page.locator("#setting-core\\.sandbox\\.provider select").selectOption("rest");

    await expect(page.getByLabel("Mapping: processes")).toBeVisible();
    await page.locator("#setting-core\\.sandbox\\.rest\\.report\\.format select").selectOption("cape2");
    await expect(page.getByLabel("Mapping: processes")).toHaveCount(0);
  });
});
