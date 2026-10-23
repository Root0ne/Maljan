import { describe, expect, it } from "vitest";
import { endpointCounts } from "@/components/analysis/networkFacts";

describe("endpoint counts (WA-L13)", () => {
  it("counts a value seen in both the capture and the strings once", () => {
    const counts = endpointCounts(
      {
        domains: [{ fqdn: "Evil.example" }],
        ips: [{ address: "1.2.3.4" }],
        urls: [],
      } as never,
      [
        { kind: "domain", value: "evil.example" },
        { kind: "domain", value: "other.example" },
        { kind: "ip", value: "1.2.3.4" },
        { kind: "url", value: "http://x/y" },
      ] as never,
    );
    expect(counts).toEqual({ domains: 2, ips: 1, urls: 1 });
  });
  it("counts the strings alone when there is no network block", () => {
    expect(endpointCounts(null, [{ kind: "domain", value: "a.test" }, { kind: "domain", value: "A.test" }] as never)).toEqual({
      domains: 1,
      ips: 0,
      urls: 0,
    });
  });
});
