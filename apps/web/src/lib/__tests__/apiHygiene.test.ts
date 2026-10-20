import { afterEach, describe, expect, it, vi } from "vitest";
import { detailMessage } from "@/lib/errors";
import { resolveApiBase } from "@/lib/apiBase";
import { api } from "@/lib/api";

afterEach(() => vi.unstubAllGlobals());

describe("detailMessage (WB-L4)", () => {
  it("passes a string detail through", () => {
    expect(detailMessage({ detail: "nope" }, "fb")).toBe("nope");
  });
  it("reads a FastAPI 422 detail list, not [object Object]", () => {
    const body = { detail: [{ loc: ["body", "name"], msg: "Field required", type: "missing" }] };
    const text = detailMessage(body, "fb");
    expect(text).not.toContain("[object Object]");
    expect(text).toContain("body.name");
    expect(text).toContain("Field required");
  });
  it("falls back when there is no readable detail", () => {
    expect(detailMessage({}, "fb")).toBe("fb");
    expect(detailMessage({ detail: { a: 1 } }, "fb")).toBe('{"a":1}');
  });
});

describe("resolveApiBase (WB-L13)", () => {
  it("uses the configured URL", () => {
    expect(resolveApiBase("https://api.example.test")).toEqual({
      base: "https://api.example.test",
      fellBack: false,
    });
  });
  it("says the loopback fallback when unset", () => {
    const r = resolveApiBase(undefined);
    expect(r.base).toBe("http://127.0.0.1:8000");
    expect(r.fellBack).toBe(true);
  });
});

describe("route ids are encoded (WB-L11)", () => {
  it("encodes a report id in the path", async () => {
    const seen: string[] = [];
    vi.stubGlobal("fetch", async (url: string) => {
      seen.push(String(url));
      return new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });
    });
    await api.getReportStix("a/../b?x=1").catch(() => undefined);
    expect(seen[0]).toContain("/reports/a%2F..%2Fb%3Fx%3D1/stix");
  });
});
