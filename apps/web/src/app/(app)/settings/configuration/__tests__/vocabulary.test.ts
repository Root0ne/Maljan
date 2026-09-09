import { describe, expect, it } from "vitest";
import { appliesSummary } from "../vocabulary";

describe("appliesSummary", () => {
  it("joins the next_job/live buckets with the on-the-next-analysis wording", () => {
    expect(appliesSummary({ next_job: 2, live: 1 }, 3)).toBe(
      "Applied 3 settings · 2 on the next analysis · 1 immediately"
    );
  });

  it("singularises the total and uses the restart wording", () => {
    expect(appliesSummary({ restart: 1 }, 1)).toBe(
      "Applied 1 setting · 1 after a restart"
    );
  });
});
