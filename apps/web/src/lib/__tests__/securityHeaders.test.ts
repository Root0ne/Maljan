import { describe, expect, it } from "vitest";

import nextConfig from "../../../next.config";
import { SECURITY_HEADERS, contentSecurityPolicy, securityHeaders } from "@/lib/securityHeaders";

describe("the headers every console page is served with", () => {
  it("refuses framing both ways a browser reads it", () => {
    const byName = Object.fromEntries(SECURITY_HEADERS.map((h) => [h.key, h.value]));
    expect(byName["X-Frame-Options"]).toBe("DENY");
    expect(byName["Content-Security-Policy"]).toContain("frame-ancestors 'none'");
    expect(byName["X-Content-Type-Options"]).toBe("nosniff");
    expect(byName["Referrer-Policy"]).toBe("no-referrer");
  });

  it("pins sources and connections to this origin plus the configured API (WA-L17)", () => {
    const csp = contentSecurityPolicy({ apiUrl: "https://api.example.test/x", wsUrl: "wss://live.example.test" });
    const d = Object.fromEntries(csp.split(";").map((p) => p.trim().split(/ (.*)/).slice(0, 2)));
    expect(d["default-src"]).toBe("'self'");
    expect(d["object-src"]).toBe("'none'");
    expect(d["base-uri"]).toBe("'self'");
    expect(d["form-action"]).toBe("'self'");
    expect(d["connect-src"]).toContain("https://api.example.test");
    expect(d["connect-src"]).toContain("wss://api.example.test");
    expect(d["connect-src"]).toContain("wss://live.example.test");
    expect(d["connect-src"]).not.toContain("*");
    expect(d["script-src"]).not.toContain("unsafe-eval");
  });

  it("dev mode keeps HMR working", () => {
    const csp = contentSecurityPolicy({ dev: true });
    expect(csp).toContain("'unsafe-eval'");
    expect(csp).toContain("ws:");
  });

  it("falls back to the loopback API when none is configured", () => {
    expect(securityHeaders({}).find((h) => h.key === "Content-Security-Policy")?.value).toContain(
      "http://127.0.0.1:8000",
    );
  });

  it("are sent on every path by the Next config", async () => {
    expect(nextConfig.headers).toBeTypeOf("function");
    const rules = await nextConfig.headers!();
    expect(rules).toEqual([{ source: "/:path*", headers: [...SECURITY_HEADERS] }]);
  });
});
