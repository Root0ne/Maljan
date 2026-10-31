import { describe, expect, it } from "vitest";

import type { CallMapFunction, CallMapResponse } from "@/types/evidence";
import { CALLEES_FIRST, byAddress, filterFunctions, readCounts, treeRows } from "../callMap";

const fn = (address: string, calls: string[] = [], over: Partial<CallMapFunction> = {}): CallMapFunction => ({
  address,
  offset: null,
  names: [],
  read: true,
  listed_in: ["ev_0001"],
  read_by: [],
  calls,
  called_by: [],
  ...over,
});

const map = (functions: CallMapFunction[], roots: string[]): CallMapResponse => ({
  job_id: "j",
  image_base: null,
  functions,
  roots,
});

describe("the call tree", () => {
  const cycle = map([fn("0x10", ["0x20"]), fn("0x20", ["0x30", "0x10"]), fn("0x30", [], { read: false, listed_in: [] })], ["0x10"]);

  it("draws only the roots until a function is opened", () => {
    const rows = treeRows(cycle.roots, byAddress(cycle), { open: new Set(), whole: new Set() });
    expect(rows.map((r) => [r.kind, r.key, r.level])).toEqual([["function", "0x10", 1]]);
  });

  it("opens a path, and a call back up the path is a marker that never opens", () => {
    const open = new Set(["0x10", "0x10>0x20", "0x10>0x20>0x10"]);
    const rows = treeRows(cycle.roots, byAddress(cycle), { open, whole: new Set() });
    expect(rows.map((r) => [r.kind, r.key, r.level, r.posinset, r.setsize])).toEqual([
      ["function", "0x10", 1, 1, 1],
      ["function", "0x10>0x20", 2, 1, 1],
      ["function", "0x10>0x20>0x30", 3, 1, 2],
      ["back", "0x10>0x20>0x10", 3, 2, 2],
    ]);
  });

  it("draws the first callees of a wide function and a row for the rest until asked", () => {
    const callees = Array.from({ length: CALLEES_FIRST + 7 }, (_, i) => `0x${(0x1000 + i).toString(16)}`);
    const wide = map([fn("0x10", callees), ...callees.map((a) => fn(a))], ["0x10"]);
    const open = new Set(["0x10"]);
    const cut = treeRows(wide.roots, byAddress(wide), { open, whole: new Set() });
    expect(cut).toHaveLength(1 + CALLEES_FIRST + 1);
    expect(cut[cut.length - 1]).toMatchObject({ kind: "more", hidden: 7, parent: "0x10" });
    const all = treeRows(wide.roots, byAddress(wide), { open, whole: new Set(["0x10"]) });
    expect(all).toHaveLength(1 + CALLEES_FIRST + 7);
  });
});

describe("the flat list", () => {
  const functions = [
    fn("0x1360bc03c7c", [], { names: ["entry"], offset: "0x3c7c" }),
    fn("0x1360bc01000", [], { read: false, listed_in: [] }),
  ];

  it("searches address, offset and name with or without 0x", () => {
    expect(filterFunctions(functions, "all", "ENTRY").map((f) => f.address)).toEqual(["0x1360bc03c7c"]);
    expect(filterFunctions(functions, "all", "3c7c")).toHaveLength(1);
    expect(filterFunctions(functions, "all", "0x1360bc0")).toHaveLength(2);
  });

  it("narrows to read or named-only functions and counts both", () => {
    expect(filterFunctions(functions, "named", "").map((f) => f.address)).toEqual(["0x1360bc01000"]);
    expect(filterFunctions(functions, "read", "")).toHaveLength(1);
    expect(readCounts(functions)).toEqual({ read: 1, named: 1 });
  });
});
