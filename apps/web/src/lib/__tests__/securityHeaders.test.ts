import { describe, expect, it } from "vitest";

import nextConfig from "../../../next.config";
import { SECURITY_HEADERS } from "@/lib/securityHeaders";

describe("the headers every console page is served with", () => {
  it("refuses framing both ways a browser reads it", () => {
    const byName = Object.fromEntries(SECURITY_HEADERS.map((h) => [h.key, h.value]));
    expect(byName["X-Frame-Options"]).toBe("DENY");
    expect(byName["Content-Security-Policy"]).toBe("frame-ancestors 'none'");
    expect(byName["X-Content-Type-Options"]).toBe("nosniff");
    expect(byName["Referrer-Policy"]).toBe("no-referrer");
  });

  it("restricts nothing but framing in the CSP, so no page loses a resource", () => {
    const csp = SECURITY_HEADERS.find((h) => h.key === "Content-Security-Policy")?.value ?? "";
    expect(csp.split(";").map((d) => d.trim()).filter(Boolean)).toEqual([
      "frame-ancestors 'none'",
    ]);
  });

  it("are sent on every path by the Next config", async () => {
    expect(nextConfig.headers).toBeTypeOf("function");
    const rules = await nextConfig.headers!();
    expect(rules).toEqual([{ source: "/:path*", headers: [...SECURITY_HEADERS] }]);
  });
});
