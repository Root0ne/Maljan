import { describe, expect, it, vi } from "vitest";

import {
  SEARCH_SOURCES,
  readSearchSources,
  searchSourcesError,
  shouldStartSearchRead,
} from "../searchSources";

describe("when the palette starts reading", () => {
  it("waits for the first character typed after opening, not the focus that opened it", () => {
    expect(shouldStartSearchRead(true, false, false)).toBe(false);
    expect(shouldStartSearchRead(true, true, false)).toBe(true);
  });

  it("reads once per opening, and never while closed", () => {
    expect(shouldStartSearchRead(true, true, true)).toBe(false);
    expect(shouldStartSearchRead(false, true, false)).toBe(false);
  });
});

describe("what the search palette says about the lists it searched", () => {
  it("says nothing when every list was read", () => {
    expect(searchSourcesError([])).toBeNull();
  });

  it("names a list that could not be read rather than answering No matches", () => {
    expect(searchSourcesError(["jobs"])).toBe("Search is incomplete — jobs could not be loaded.");
    expect(searchSourcesError(["samples", "jobs", "reports"])).toBe(
      "Search unavailable — could not reach the API.",
    );
  });
});

describe("reading the lists the palette searches", () => {
  it("reads each list once and names only the one that failed", async () => {
    const read = vi.fn(async (source: string) => {
      if (source === "jobs") throw new Error("502");
      return source.length;
    });
    const outcome = await readSearchSources(SEARCH_SOURCES, read, new AbortController().signal);
    expect(read).toHaveBeenCalledTimes(3);
    expect(outcome).toEqual({ data: { samples: 7, reports: 7 }, failed: ["jobs"] });
  });

  it("retries only the list that failed", async () => {
    const read = vi.fn(async (source: string) => source.length);
    const outcome = await readSearchSources(["jobs"], read, new AbortController().signal);
    expect(read.mock.calls.map(([source]) => source)).toEqual(["jobs"]);
    expect(outcome?.failed).toEqual([]);
  });

  it("answers nothing once the palette closed and the read was aborted", async () => {
    const controller = new AbortController();
    const read = vi.fn(async (_source: string, signal: AbortSignal) => {
      controller.abort();
      signal.throwIfAborted();
      return 1;
    });
    expect(await readSearchSources(SEARCH_SOURCES, read, controller.signal)).toBeNull();
  });
});
