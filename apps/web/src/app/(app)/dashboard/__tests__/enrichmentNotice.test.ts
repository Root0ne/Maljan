/**
 * What the dashboard says about the enrichment worker.
 *
 * One state is worth a line and the rest are not, so the test is mostly about
 * silence: a console that announced "not_required" would be telling every
 * single-process install about a worker it does not have.
 */

import { describe, expect, it } from "vitest";

import {
  ENRICHMENT_WORKER_SETTING,
  enrichmentWorkerNotice,
} from "@/app/(app)/dashboard/enrichmentNotice";

describe("the enrichment worker notice", () => {
  it("says nothing when the status does not carry the field", () => {
    expect(enrichmentWorkerNotice(undefined)).toBeNull();
    expect(enrichmentWorkerNotice(null)).toBeNull();
  });

  it("says nothing while enrichment has somewhere to run", () => {
    expect(enrichmentWorkerNotice("up")).toBeNull();
    expect(enrichmentWorkerNotice("not_required")).toBeNull();
    // A queue the status call could not read is not a queue known to be idle.
    expect(enrichmentWorkerNotice("unknown")).toBeNull();
  });

  it("says what is waiting, and names the setting it is waiting on", () => {
    const notice = enrichmentWorkerNotice("down");

    expect(notice).not.toBeNull();
    expect(notice?.label).toBe("Enrichment waiting");
    expect(notice?.detail).toContain("no such worker is reading the queue");
    expect(notice?.setting).toBe(ENRICHMENT_WORKER_SETTING);
    expect(ENRICHMENT_WORKER_SETTING).toBe("api.enrichment_dedicated_worker");
  });
});
