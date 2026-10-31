import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { MalwareReport, ProcessNode } from "@/types/malware-report";
import { behaviourPids, processRows, subtreeSize, type ProcessRow } from "../processTree";
import ProcessTree, { ProcessDetail } from "../tabs/ProcessTree";

function node(pid: number, name: string, children: ProcessNode[] = [], extra: Partial<ProcessNode> = {}): ProcessNode {
  return { pid, ppid: 0, name, command_line: "", children, injected_into: [], ...extra };
}

const CLOSED = { open: {}, unfolded: new Set<string>() };
const names = (rows: ProcessRow[]) =>
  rows.map((r) => `${"  ".repeat(r.depth)}${r.kind === "fold" ? `+${r.count}` : r.node.name}`);

/* A system tree with the sample two levels down, beside two benign branches. */
const TREE: ProcessNode[] = [
  node(4, "System", [
    node(400, "services.exe", [node(500, "svchost.exe", [node(510, "dllhost.exe")]), node(600, "spoolsv.exe")]),
    node(700, "explorer.exe", [node(1024, "invoice.exe", [node(1180, "cmd.exe")], { marked: true })]),
  ]),
];

describe("the sample's path through the process tree (T-465)", () => {
  it("opens the path to a marked process and what it started, and folds the rest", () => {
    expect(names(processRows(TREE, new Map(), CLOSED))).toEqual([
      "System",
      "  explorer.exe",
      "    invoice.exe",
      "      cmd.exe",
      "  +4",
    ]);
  });

  it("flags a process by its mark, by an injection, or by a pid another field ties to it", () => {
    const rows = processRows(
      [node(1, "a", [node(2, "b", [], { injected_into: [9] }), node(3, "c"), node(5, "d")])],
      new Map([[3, ["made a DNS query"]]]),
      CLOSED,
    ).filter((r): r is Extract<ProcessRow, { kind: "process" }> => r.kind === "process");
    expect(rows.map((r) => [r.node.name, r.flagged])).toEqual([
      ["a", false],
      ["b", true],
      ["c", true],
    ]);
    expect(rows[1].reasons).toEqual(["injects into 9"]);
    expect(rows[2].reasons).toEqual(["made a DNS query"]);
  });

  it("opens a fold, and the processes it held arrive closed", () => {
    const rows = processRows(TREE, new Map(), { open: {}, unfolded: new Set(["0"]) });
    expect(names(rows)).toEqual(["System", "  services.exe", "  explorer.exe", "    invoice.exe", "      cmd.exe"]);
  });

  it("lets the reader's own toggle win over the default", () => {
    const rows = processRows(TREE, new Map(), { open: { "0.1": false }, unfolded: new Set() });
    expect(names(rows)).toEqual(["System", "  explorer.exe", "  +4"]);
  });

  it("opens the first two levels of a tree with nothing flagged, and folds nothing", () => {
    const plain = [node(1, "a", [node(2, "b", [node(3, "c", [node(4, "d")])])])];
    expect(names(processRows(plain, new Map(), CLOSED))).toEqual(["a", "  b", "    c"]);
  });

  it("counts a fold's descendants", () => {
    expect(subtreeSize(TREE)).toBe(8);
  });
});

describe("the pids other fields tie to a behaviour", () => {
  it("reads a domain's querying pids and a registry write's pids", () => {
    const mr = {
      network: { domains: [{ fqdn: "x.test", queried_pids: [1024] }] },
      dynamic: { registry_mods: [{ pids: ["1180", "junk"] }] },
    } as unknown as MalwareReport;
    const tied = behaviourPids(mr);
    expect(tied.get(1024)).toEqual(["made a DNS query"]);
    expect(tied.get(1180)).toEqual(["wrote to the registry"]);
    expect(tied.size).toBe(2);
  });
});

describe("a process stored without its lists", () => {
  // A row persisted before `children` or `injected_into` were written.
  const bare = { pid: 77, ppid: 1, name: "bare.exe", command_line: "bare.exe /x" } as unknown as ProcessNode;

  it("is a leaf with no injection, in the rows and on the page", () => {
    const rows = processRows([bare], new Map(), CLOSED);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ kind: "process", hasChildren: false, flagged: false });
    const html = renderToStaticMarkup(createElement(ProcessTree, { roots: [bare], mr: null }));
    expect(html).toContain("bare.exe");
    expect(html).not.toContain("injects into");
  });

  it("opens in the side panel with no children and nothing injected", () => {
    const row = processRows([bare], new Map(), CLOSED)[0] as Extract<ProcessRow, { kind: "process" }>;
    const html = renderToStaticMarkup(createElement(ProcessDetail, { row }));
    expect(html).toContain("Nothing recorded");
    expect(html).toMatch(/Child processes<\/dt><dd[^>]*>0</);
  });
});
