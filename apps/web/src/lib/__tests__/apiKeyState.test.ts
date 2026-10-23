import { describe, expect, it } from "vitest";
import { apiKeyState, lastUsedText } from "@/app/(app)/settings/api-keys/keyState";

describe("api key state (WA-L11)", () => {
  const now = Date.parse("2026-10-20T00:00:00Z");
  it("an expired key is not Active", () => {
    expect(apiKeyState({ is_active: true, expires_at: "2026-10-01T00:00:00Z" }, now)).toBe("expired");
  });
  it("a live key, a no-expiry key and a revoked key", () => {
    expect(apiKeyState({ is_active: true, expires_at: "2027-01-01T00:00:00Z" }, now)).toBe("active");
    expect(apiKeyState({ is_active: true, expires_at: null }, now)).toBe("active");
    expect(apiKeyState({ is_active: false, expires_at: "2027-01-01T00:00:00Z" }, now)).toBe("revoked");
  });
  it("says never used, and when it was", () => {
    expect(lastUsedText(null, String)).toBe("Never used");
    expect(lastUsedText("x", (s) => `<${s}>`)).toBe("Last used <x>");
  });
});
