/**
 * The preview route answers 404 unless the build opts in.
 *
 * The end-to-end suite runs with the flag on (it covers the page), so the
 * flag-off answer is pinned here, on the route's own layout: with
 * NEXT_PUBLIC_UI_NEXT unset or "false" it throws Next's not-found, and with
 * "true" it renders the frame.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import AnalysisPreviewLayout from "@/app/(app)/preview/analysis/[id]/layout";

const call = () => AnalysisPreviewLayout({ children: null, params: Promise.resolve({ id: "job-1" }) });

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("the preview route", () => {
  for (const value of [undefined, "", "false", "0"]) {
    it(`is not found when the flag is ${JSON.stringify(value)}`, async () => {
      vi.stubEnv("NEXT_PUBLIC_UI_NEXT", value as string);
      await expect(call()).rejects.toMatchObject({ digest: expect.stringContaining("404") });
    });
  }

  it("renders the frame when the flag is on", async () => {
    vi.stubEnv("NEXT_PUBLIC_UI_NEXT", "true");
    const out = await call();
    expect(out).toBeTruthy();
  });
});
