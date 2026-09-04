import { test, expect } from "./fixtures";

/**
 * The submit dialog on /samples: two optional provider selects and an
 * "Attach sandbox report" input. "Inherit from settings" is the default for
 * both selects and sends no key at all, so an operator who has configured the
 * providers once never sees the difference.
 */
test.describe("Job submission with providers", () => {
  test("submitting without touching the selects sends today's payload", async ({
    authenticatedPage: page,
  }) => {
    const bodies: unknown[] = [];
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") {
        bodies.push(r.request().postDataJSON());
        return r.fulfill({ status: 201, json: { id: "job-1", status: "pending" } });
      }
      return r.fallback();
    });

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await page.getByRole("button", { name: "Start analysis" }).click();

    expect(bodies).toHaveLength(1);
    expect(bodies[0]).toMatchObject({ config: null });
  });

  test("choosing providers sends them in the job config", async ({
    authenticatedPage: page,
  }) => {
    const bodies: unknown[] = [];
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") {
        bodies.push(r.request().postDataJSON());
        return r.fulfill({ status: 201, json: { id: "job-2", status: "pending" } });
      }
      return r.fallback();
    });

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await page.getByLabel("Static provider").selectOption("capa_yara");
    await page.getByLabel("Sandbox provider").selectOption("triage");
    await page.getByRole("button", { name: "Start analysis" }).click();

    expect(bodies[0]).toMatchObject({
      config: { static_provider: "capa_yara", sandbox_provider: "triage" },
    });
  });

  test("attaching a report uploads it and pins the job to the upload provider", async ({
    authenticatedPage: page,
  }) => {
    const bodies: unknown[] = [];
    await page.route("**/api/v1/samples/*/sandbox-reports", (r) =>
      r.request().method() === "POST"
        ? r.fulfill({
            status: 201,
            json: {
              id: "rep-1", format: "cape2", task_id: "4242", size_bytes: 1234,
              sample_sha256_match: true, warning: null,
              uploaded_at: "2026-09-04T10:00:00Z",
            },
          })
        : r.fulfill({ json: { items: [], total: 0 } })
    );
    await page.route("**/api/v1/jobs", (r) => {
      if (r.request().method() === "POST") {
        bodies.push(r.request().postDataJSON());
        return r.fulfill({ status: 201, json: { id: "job-3", status: "pending" } });
      }
      return r.fallback();
    });

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await page.getByLabel("Attach sandbox report").setInputFiles({
      name: "report.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify({ info: { version: "CAPEv2", id: 4242 } })),
    });
    await expect(page.getByText("cape2 · task 4242")).toBeVisible();
    await page.getByRole("button", { name: "Start analysis" }).click();

    expect(bodies[0]).toMatchObject({ config: { sandbox_report_id: "rep-1" } });
  });

  test("a hash mismatch on the uploaded report is shown before submitting", async ({
    authenticatedPage: page,
  }) => {
    await page.route("**/api/v1/samples/*/sandbox-reports", (r) =>
      r.request().method() === "POST"
        ? r.fulfill({
            status: 201,
            json: {
              id: "rep-2", format: "cape2", task_id: null, size_bytes: 10,
              sample_sha256_match: false,
              warning: "The report's target sha256 (cccccccccccc…) does not match this sample.",
              uploaded_at: "2026-09-04T10:00:00Z",
            },
          })
        : r.fulfill({ json: { items: [], total: 0 } })
    );

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await page.getByLabel("Attach sandbox report").setInputFiles({
      name: "other.json",
      mimeType: "application/json",
      buffer: Buffer.from("{}"),
    });
    // Scoped to the dialog: a bare page-wide getByRole("alert") also matches
    // Next's permanent #__next-route-announcer__ (see fixtures.ts), which
    // trips strict mode here since both elements share the role.
    await expect(page.getByRole("dialog").getByRole("alert")).toContainText(
      "does not match this sample"
    );
  });
});
