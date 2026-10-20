import { describe, expect, it } from "vitest";
import { ApiError, isForbidden } from "@/lib/errors";

describe("isForbidden (WA-L15)", () => {
  it("is true only for a 403 the API answered", () => {
    expect(isForbidden(new ApiError("Admin role required", 403))).toBe(true);
  });
  it("an error that merely mentions admin or 403 is not forbidden", () => {
    expect(isForbidden(new ApiError("admin settings table missing", 500))).toBe(false);
    expect(isForbidden(new Error("failed to load admin schema"))).toBe(false);
    expect(isForbidden(new Error("HTTP 403"))).toBe(false);
  });
});
