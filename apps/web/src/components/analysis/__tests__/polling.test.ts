import { describe, expect, it } from "vitest";

import { ApiError, parseRetryAfter } from "@/lib/errors";
import { POLL_INTERVAL_MS, pollDelay, pollFailure, pollNotice, reportFetchError } from "../polling";

describe("a failed poll of the job", () => {
  it("ends the polling on a 404, which says the job does not exist", () => {
    expect(pollFailure(new ApiError("Not found", 404))).toEqual({ kind: "not-found" });
  });

  it("is retried when the API gave no answer or a 5xx", () => {
    expect(pollFailure(new TypeError("Failed to fetch"))).toEqual({
      kind: "retry",
      message: "Failed to fetch",
      retryAfterMs: null,
    });
    expect(pollFailure(new ApiError("Bad gateway", 502))).toEqual({
      kind: "retry",
      message: "Bad gateway",
      retryAfterMs: null,
    });
  });

  it("is retried on a request timeout and a rate limit, which are not refusals", () => {
    expect(pollFailure(new ApiError("Request timeout", 408)).kind).toBe("retry");
    expect(pollFailure(new ApiError("Too many requests", 429, 20_000))).toEqual({
      kind: "retry",
      message: "Too many requests",
      retryAfterMs: 20_000,
    });
  });

  it("waits as long as Retry-After asks when that is longer than the backoff", () => {
    expect(pollDelay(0, 20_000)).toBe(20_000);
    expect(pollDelay(0, 1_000)).toBe(POLL_INTERVAL_MS);
    expect(pollDelay(0, null)).toBe(POLL_INTERVAL_MS);
  });

  it("reads Retry-After as seconds or as a date", () => {
    expect(parseRetryAfter("20")).toBe(20_000);
    const now = Date.parse("2026-10-20T10:00:00Z");
    expect(parseRetryAfter("Tue, 20 Oct 2026 10:00:30 GMT", now)).toBe(30_000);
    expect(parseRetryAfter(null)).toBeNull();
    expect(parseRetryAfter("soon")).toBeNull();
  });

  it("stops, with the server's words, on a refusal asking again will not change", () => {
    for (const status of [401, 403, 422]) {
      expect(pollFailure(new ApiError(`said ${status}`, status))).toEqual({
        kind: "stop",
        message: `said ${status}`,
      });
    }
  });

  it("backs off between retries", () => {
    expect(pollDelay(0)).toBe(POLL_INTERVAL_MS);
    expect(pollDelay(1)).toBe(POLL_INTERVAL_MS * 2);
    expect(pollDelay(3)).toBe(POLL_INTERVAL_MS * 8);
    expect(pollDelay(50)).toBe(60_000);
  });
});

describe("the banner while polls fail", () => {
  it("is drawn after the page has loaded once, not only before", () => {
    expect(pollNotice("Failed to fetch", true)).toMatch(/^Lost contact with the API \(Failed to fetch\)/);
    expect(pollNotice("Failed to fetch", false)).toMatch(/^Could not connect to the API/);
  });

  it("says polling stopped on a refusal", () => {
    expect(pollNotice("Not authenticated", true, true)).toMatch(/^The API refused this page \(Not authenticated\)/);
  });

  it("goes away once a poll answers", () => {
    expect(pollNotice(null, true)).toBeNull();
  });
});

describe("a failed read of a finished run's report", () => {
  it("is an absence, not an error, when the API answers 404", () => {
    expect(reportFetchError(new ApiError("Report not found", 404), true)).toBeNull();
  });

  it("is an error for any other failure", () => {
    expect(reportFetchError(new ApiError("Internal error", 500), true)).toBe("Internal error");
  });

  it("is expected while the run is still going", () => {
    expect(reportFetchError(new ApiError("Internal error", 500), false)).toBeNull();
  });
});
