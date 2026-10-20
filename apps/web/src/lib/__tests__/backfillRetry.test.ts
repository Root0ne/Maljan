import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "@/lib/errors";
import {
  configureRunTransport,
  getRun,
  resetRun,
  subscribeRun,
  type IncomingEvent,
  type RunTransport,
} from "@/lib/runStore";

const JOB = "job-retry";

function transportFailing(errors: unknown[], feed: IncomingEvent[]) {
  let reads = 0;
  const transport: RunTransport = {
    async readEvents() {
      const error = errors[reads++];
      if (error) throw error;
      return feed;
    },
    connect() {
      return { close() {} };
    },
  };
  return { transport, reads: () => reads };
}

beforeEach(() => vi.useFakeTimers());
afterEach(() => {
  vi.useRealTimers();
  resetRun(JOB);
  configureRunTransport(null);
});

describe("back-fill retry (WB-L5)", () => {
  it("asks again after a 5xx, honouring Retry-After, then clears the failure", async () => {
    const feed: IncomingEvent[] = [{ type: "stage_started", data: { stage: "a" }, ts: "t", stream_id: "1-0" }];
    const { transport, reads } = transportFailing([new ApiError("boom", 503, 20_000)], feed);
    configureRunTransport(transport);
    const off = subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(0);
    expect(reads()).toBe(1);
    expect(getRun(JOB).feedError).toContain("boom");
    await vi.advanceTimersByTimeAsync(19_000);
    expect(reads()).toBe(1);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(reads()).toBe(2);
    expect(getRun(JOB).feedError).toBeNull();
    off();
  });

  it("does not retry a refusal, and says it", async () => {
    const { transport, reads } = transportFailing([new ApiError("Forbidden", 403)], []);
    configureRunTransport(transport);
    const off = subscribeRun(JOB, () => {});
    await vi.advanceTimersByTimeAsync(120_000);
    expect(reads()).toBe(1);
    expect(getRun(JOB).feedError).toContain("Forbidden");
    off();
  });
});
