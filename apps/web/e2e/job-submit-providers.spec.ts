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

  test("closing the dialog for one sample does not leak its report onto the next", async ({
    authenticatedPage: page,
  }) => {
    // M9 regression: closing the dialog while an upload is in flight used to
    // leave it un-cancelled, so a response that resolved after a *different*
    // sample's dialog was already open attached the wrong sample's report.
    await page.route("**/api/v1/samples?**", (r) =>
      r.fulfill({
        status: 200,
        json: {
          items: [
            { id: "sample-a", sha256: "a".repeat(64), md5: "a".repeat(32), original_filename: "first.exe", file_size_bytes: 100, mime_type: "application/x-dosexec", uploaded_at: "2026-09-04T10:00:00Z" },
            { id: "sample-b", sha256: "b".repeat(64), md5: "b".repeat(32), original_filename: "second.exe", file_size_bytes: 100, mime_type: "application/x-dosexec", uploaded_at: "2026-09-04T10:00:00Z" },
          ],
          total: 2, page: 1, page_size: 50,
        },
      })
    );
    await page.route("**/api/v1/samples/sample-a/sandbox-reports", async (r) => {
      if (r.request().method() !== "POST") return r.fulfill({ json: { items: [], total: 0 } });
      // Resolves only after the test has moved the dialog on to sample-b.
      await new Promise((resolve) => setTimeout(resolve, 300));
      return r.fulfill({
        status: 201,
        json: {
          id: "rep-a", format: "cape2", task_id: "1111", size_bytes: 10,
          sample_sha256_match: true, warning: null, uploaded_at: "2026-09-04T10:00:00Z",
        },
      });
    });
    await page.route("**/api/v1/samples/sample-b/sandbox-reports", (r) =>
      r.request().method() === "POST"
        ? r.fulfill({ status: 500, json: { detail: "not used in this test" } })
        : r.fulfill({ json: { items: [], total: 0 } })
    );

    await page.goto("/samples");
    await page.getByRole("button", { name: "Analyze" }).first().click();
    await expect(page.getByRole("dialog")).toContainText("Analyze first.exe");
    await page.getByLabel("Attach sandbox report").setInputFiles({
      name: "report.json",
      mimeType: "application/json",
      buffer: Buffer.from(JSON.stringify({ info: { version: "CAPEv2", id: 1111 } })),
    });
    // Close before sample-a's upload response arrives, then open sample-b's
    // dialog — the in-flight request for sample-a is still pending.
    await page.getByRole("button", { name: "Cancel" }).click();
    await page.getByRole("button", { name: "Analyze" }).nth(1).click();
    await expect(page.getByRole("dialog")).toContainText("Analyze second.exe");

    // Give sample-a's delayed response time to resolve in the background.
    await page.waitForTimeout(500);
    await expect(page.getByText("cape2 · task 1111")).not.toBeVisible();
  });
});
