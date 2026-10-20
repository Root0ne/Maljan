import { describe, expect, it } from "vitest";

import type { NetworkDomain, NetworkIP } from "@/types/malware-report";
import { domainFacts, ipFacts } from "../networkFacts";

function ip(over: Partial<NetworkIP> = {}): NetworkIP {
  return {
    address: "203.0.113.7",
    port: 443,
    transport: "tcp",
    asn: null,
    geo: null,
    is_suspicious: false,
    reputation: null,
    ...over,
  };
}

function domain(over: Partial<NetworkDomain> = {}): NetworkDomain {
  return {
    fqdn: "c2.example",
    queried_pids: [],
    resolved_ips: [],
    is_suspicious: false,
    reason: null,
    dga_score: null,
    is_punycode: false,
    homograph_target: null,
    source: "sandbox",
    reputation: null,
    ...over,
  };
}

describe("what an address row says about who reached it", () => {
  it("says nothing the row does not carry: an unset tree flag is not a no", () => {
    expect(ipFacts(ip())).toEqual([]);
    expect(ipFacts(ip({ sample_process_tree: null }))).toEqual([]);
  });

  it("says the sample's tree reached it, or names the processes that did instead", () => {
    expect(ipFacts(ip({ sample_process_tree: true }))).toEqual([
      "The sandbox saw the sample's own process tree reach this address.",
    ]);
    expect(
      ipFacts(ip({ sample_process_tree: false, outside_processes: ["svchost.exe (procid 4)"] })),
    ).toEqual([
      "Every flow the sandbox attributes came from outside the sample's tree: svchost.exe (procid 4).",
    ]);
  });

  it("names the processes the two lineage facts disagree about, and a public resolver", () => {
    expect(
      ipFacts(
        ip({
          marked_only_processes: ["a.exe (procid 9)"],
          marked_by: "Sandbox A",
          file_only_processes: ["b.exe (procid 10)"],
          public_resolver: true,
        }),
      ),
    ).toEqual([
      "Named the sample's only by Sandbox A's own mark: a.exe (procid 9).",
      "Named the sample's only by the submitted file's process tree: b.exe (procid 10).",
      "A public DNS resolver, which a sandbox guest reaches whatever the sample does.",
    ]);
  });

  it("says who kept the value and who only mentioned it", () => {
    expect(ipFacts(ip({ kept_by: ["network"], mentioned_by: ["static", "judge"] }))).toEqual([
      "Kept as an indicator by network.",
      "Mentioned without being kept by static, judge.",
    ]);
  });
});

describe("what a domain row says", () => {
  it("says a name only the capture's TLS names recorded", () => {
    expect(domainFacts(domain({ capture_only: true }))[0]).toMatch(/only in the capture's TLS names/);
    expect(domainFacts(domain())).toEqual([]);
  });
});
