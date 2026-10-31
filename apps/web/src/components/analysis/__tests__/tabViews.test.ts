/**
 * How the Behaviour, Network, Static & code and Indicators tabs sort what the
 * report holds (T-465): every rule here reads a field by what it is, never by
 * the tool that wrote it.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useParams: () => ({ id: "J1" }) }));

import type { EvidenceSection, MalwareReport, NetworkIOCs, SandboxSignature, StringIOC } from "@/types/malware-report";
import { MALWARE_REPORT } from "../../../../e2e/report-fixture";
import { signatureGroups, techniqueTactics, techniqueUnder, viewKeeps, viewOfHash } from "../behaviourView";
import { exportCounts, exportState, filterIocs, iocFacets, iocRows, relatedFindings } from "../iocList";
import { IocDetail } from "../IocBrowser";
import { hostRows, urlHost } from "../networkView";
import { filterStrings, staticSlots, stringFacets } from "../staticView";
import { BATCH_DECOMPILE, FUNCTIONS_EXAMINED, STRINGS_SECTION } from "./storedRunShapes";

const sig = (name: string, severity: number | null, technique_ids: string[] = []): SandboxSignature => ({
  name,
  description: "",
  severity,
  technique_ids,
  marks: [],
});

describe("Behaviour: signatures by severity, then technique", () => {
  const scale = { name: "1–10", max: 10, rungs: ["Informational", "Low", "Low", "Low", "Medium", "Medium", "High", "High", "Critical", "Critical"] as const };

  it("leads with the worst rung, groups by first technique, and puts the unrated last", () => {
    const groups = signatureGroups(
      [sig("low", 2, ["T1082"]), sig("inject", 8, ["T1055"]), sig("odd", null), sig("inject2", 7, ["T1055", "T1106"]), sig("crit", 10)],
      { ...scale, rungs: [...scale.rungs] },
    );
    expect(groups.map((g) => [g.rung, g.count])).toEqual([
      ["Critical", 1],
      ["High", 2],
      ["Low", 1],
      [null, 1],
    ]);
    expect(groups[1].techniques).toHaveLength(1);
    expect(groups[1].techniques[0].technique).toBe("T1055");
    expect(groups[1].techniques[0].rows[0].sandboxText).toBe("High, 8/10");
  });

  it("keeps a sandbox number with no scale, unrated and as it came", () => {
    const [group] = signatureGroups([sig("x", 3)], null);
    expect(group.rung).toBeNull();
    expect(group.techniques[0].rows[0].sandboxText).toBe("unrated, 3");
  });
});

describe("Behaviour: persistence and defence evasion are views", () => {
  const tactics = techniqueTactics({
    capability_matrix: [
      { tactic: "TA0003", technique_id: "T1547", technique_name: "Boot or Logon Autostart Execution" },
      { tactic: "TA0005", technique_id: "T1055", technique_name: "Process Injection" },
    ],
  } as unknown as MalwareReport);

  it("reads a technique's tactic from the run's own mapping, a sub-technique under its parent", () => {
    expect(techniqueUnder("T1547.001", "TA0003", tactics)).toBe(true);
    expect(techniqueUnder("T1055", "TA0003", tactics)).toBe(false);
    expect(viewKeeps("defence-evasion", ["T1082", "T1055"], tactics)).toBe(true);
    expect(viewKeeps("persistence", [], tactics)).toBe(false);
    expect(viewKeeps("all", [], tactics)).toBe(true);
  });

  it("opens the view an address names", () => {
    expect(viewOfHash("#persistence")).toBe("persistence");
    expect(viewOfHash("#defense-evasion")).toBe("defence-evasion");
    expect(viewOfHash("#attack")).toBeNull();
  });
});

describe("Network: hosts and the requests each received", () => {
  const net = {
    domains: [{ fqdn: "CDN.example.test" }],
    ips: [{ address: "203.0.113.5" }],
    urls: [{ url: "https://cdn.example.test/gate.php" }, { url: "http://203.0.113.5:8080/x" }, { url: "elsewhere.test/y" }],
    user_agents: [],
    ja3_fingerprints: [],
    ja3s_fingerprints: [],
  } as unknown as NetworkIOCs;

  it("reads a URL's host, with or without a scheme", () => {
    expect(urlHost("https://A.test:443/p?q")).toBe("a.test");
    expect(urlHost("b.test/path")).toBe("b.test");
    expect(urlHost("")).toBe("");
  });

  it("lists domains then addresses, each with the requests its URLs name", () => {
    const rows = hostRows(net);
    expect(rows.map((r) => [r.kind, r.host, r.requests.length])).toEqual([
      ["domain", "CDN.example.test", 1],
      ["ip", "203.0.113.5", 1],
    ]);
  });
});

describe("Static & code: where each section is drawn", () => {
  const section = (key: string): EvidenceSection => ({ ...STRINGS_SECTION, key });

  it("places sections by their key's shape and listings by their cells", () => {
    const slots = staticSlots([
      section("pe_sections"),
      section("artifact_imports"),
      section("elf_exports"),
      STRINGS_SECTION,
      FUNCTIONS_EXAMINED,
      BATCH_DECOMPILE,
      section("capa_capabilities"),
    ]);
    expect(slots.structure.sections.map((s) => s.key)).toEqual(["pe_sections"]);
    expect(slots.structure.imports.map((s) => s.key)).toEqual(["artifact_imports"]);
    expect(slots.structure.exports.map((s) => s.key)).toEqual(["elf_exports"]);
    expect(slots.strings.map((s) => s.key)).toEqual(["strings"]);
    expect(slots.functions.map((s) => s.key)).toEqual(["functions_examined", "tool_batch_decompile"]);
    expect(slots.other.map((s) => s.key)).toEqual(["capa_capabilities"]);
  });

  it("facets strings by kind in reading order and searches value and notes", () => {
    const strings: StringIOC[] = [
      { value: "a.test", kind: "domain", notes: null },
      { value: "hunter2", kind: "secret", notes: "password" },
      { value: "b.test", kind: "domain", notes: "C2 candidate" },
    ];
    expect(stringFacets(strings)).toEqual([
      { kind: "secret", count: 1 },
      { kind: "domain", count: 2 },
    ]);
    expect(filterStrings(strings, "domain", "").length).toBe(2);
    expect(filterStrings(strings, "all", "c2").map((s) => s.value)).toEqual(["b.test"]);
  });
});

describe("Indicators: one browsable list", () => {
  const mr = MALWARE_REPORT as unknown as MalwareReport;

  it("merges the verdict's values into the table's rows and keeps the rest as their own", () => {
    const rows = iocRows({
      ...mr,
      judge_indicators: [...(mr.judge_indicators ?? []), { kind: "domain", value: "only.verdict.test", algorithm: "" }],
    });
    expect(rows.map((r) => [r.value.slice(0, 16), r.inVerdict, r.decision?.publication ?? null])).toEqual([
      [mr.consolidated_iocs![0].value.slice(0, 16), true, "published"],
      ["8.8.8.8", false, "withheld"],
      ["only.verdict.tes", true, null],
    ]);
    expect(rows[0].algorithm).toBe("SHA-256");
  });

  it("facets by type and filters by type, search and export decision", () => {
    const rows = iocRows(mr);
    expect(iocFacets(rows)).toEqual([
      { type: "SHA-256", count: 1 },
      { type: "IPv4", count: 1 },
    ]);
    expect(filterIocs(rows, { type: "IPv4", query: "", publication: "all" }).map((r) => r.value)).toEqual(["8.8.8.8"]);
    expect(filterIocs(rows, { type: null, query: "", publication: "published" })).toHaveLength(1);
    expect(filterIocs(rows, { type: null, query: "resolver", publication: "all" }).map((r) => r.value)).toEqual(["8.8.8.8"]);
  });

  it("counts and filters withheld only where the rule answered no", () => {
    const rows = iocRows({
      ...mr,
      consolidated_iocs: [
        ...(mr.consolidated_iocs ?? []),
        { type: "Mutex", kind: "mutex", value: "Global\\M1", source: "sandbox", context: "", published: null, is_network: false, description: "", recovered_by: "" },
      ],
      judge_indicators: [...(mr.judge_indicators ?? []), { kind: "domain", value: "only.verdict.test", algorithm: "" }],
    } as MalwareReport);
    expect(rows.map(exportState)).toEqual(["published", "withheld", "unanswered", "not-in-table"]);
    expect(exportCounts(rows)).toEqual({ published: 1, withheld: 1, unanswered: 1, "not-in-table": 1 });
    expect(filterIocs(rows, { type: null, query: "", publication: "withheld" }).map((r) => r.value)).toEqual(["8.8.8.8"]);
    expect(filterIocs(rows, { type: null, query: "", publication: "unanswered" }).map((r) => r.value)).toEqual(["Global\\M1"]);
    expect(filterIocs(rows, { type: null, query: "", publication: "not-in-table" }).map((r) => r.value)).toEqual([
      "only.verdict.test",
    ]);
  });

  it("matches a verdict value to a table row of its kind, or to a row stored without one", () => {
    const table = (over: Partial<NonNullable<MalwareReport["consolidated_iocs"]>[number]>) => ({
      type: "Domain", kind: "domain", value: "x.test", source: "sandbox", context: "", published: "yes", is_network: true, description: "", recovered_by: "",
      ...over,
    });
    // The same value under another kind is another indicator.
    const other = iocRows({ consolidated_iocs: [table({})], judge_indicators: [{ kind: "url", value: "X.test", algorithm: "" }] } as unknown as MalwareReport);
    expect(other.map((r) => [r.kind, r.inVerdict, r.decision === null])).toEqual([
      ["domain", false, false],
      ["url", true, true],
    ]);
    // A row stored before the table carried kinds matches on the value alone.
    const old = iocRows({ consolidated_iocs: [table({ kind: "" })], judge_indicators: [{ kind: "url", value: "x.test", algorithm: "" }] } as unknown as MalwareReport);
    expect(old.map((r) => r.inVerdict)).toEqual([true]);
  });

  it("keeps every entry a verdict gives one table row, and draws each in its panel", () => {
    const sha = mr.consolidated_iocs![0].value;
    const repeated = {
      ...mr,
      judge_indicators: [
        { kind: "hash", value: sha, algorithm: "SHA-256" },
        { kind: "hash", value: sha.toUpperCase(), algorithm: "SHA-256 (upper case)" },
      ],
    } as MalwareReport;
    const rows = iocRows(repeated);
    expect(rows).toHaveLength(2);
    expect(rows[0].verdictEntries).toEqual([
      { kind: "hash", algorithm: "SHA-256" },
      { kind: "hash", algorithm: "SHA-256 (upper case)" },
    ]);
    const html = renderToStaticMarkup(createElement(IocDetail, { row: rows[0], mr: repeated }));
    expect(html).toContain("hash, as SHA-256<");
    expect(html).toContain("hash, as SHA-256 (upper case)");
  });

  it("finds what else the report says about a value, field by field", () => {
    const related = relatedFindings(mr, "cdn.example-update.net");
    expect(related.map((f) => f.where)).toEqual(["Network host", "HTTP request", "String in the sample"]);
    expect(relatedFindings(mr, "185.199.110.153").map((f) => f.where)).toContain("Network host");
    expect(relatedFindings(mr, "")).toEqual([]);
  });
});
