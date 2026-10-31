import { describe, expect, it } from "vitest";
import type { MalwareReport } from "@/types/malware-report";
import { exportState, iocRows, sortedForReading } from "../iocList";

const row = (type: string, value: string, published: string | null) => ({ type, value, kind: type.toLowerCase(), published });

describe("the order the Indicators list opens in", () => {
  const mr = {
    consolidated_iocs: [
      row("URL", "http://a.test", "no: benign"),
      row("Mutex", "Global\\M", "no: local"),
      row("Domain", "z.test", "yes"),
      row("SHA-256", "ab", "yes: identity"),
      row("Domain", "b.test", "no: x"),
      row("Domain", "a.test", "yes"),
    ],
  } as unknown as MalwareReport;

  it("puts published rows first and keeps the table order inside each state", () => {
    const sorted = sortedForReading(iocRows(mr));
    expect(sorted.map((r) => r.value)).toEqual(["z.test", "ab", "a.test", "http://a.test", "Global\\M", "b.test"]);
    expect(sorted.slice(0, 3).every((r) => exportState(r) === "published")).toBe(true);
  });

  it("leaves its input alone", () => {
    const rows = iocRows(mr);
    const before = rows.map((r) => r.key);
    const sorted = sortedForReading(rows);
    expect(rows.map((r) => r.key)).toEqual(before);
    const domains = sorted.filter((r) => r.type === "Domain" && exportState(r) === "published");
    expect(domains.map((r) => r.value)).toEqual(["z.test", "a.test"]);
  });
});
