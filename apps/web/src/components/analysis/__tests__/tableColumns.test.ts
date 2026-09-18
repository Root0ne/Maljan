import { describe, expect, it } from "vitest";
import { withoutConstantColumns } from "../tableColumns";

const columns = ["Kind", "Value", "Evidence", "Notes"];
const rows = [
  ["path", "C:\\Windows\\System32", "ev_0006", "–"],
  ["path", "C:\\Users\\Public", "ev_0006", "–"],
  ["path", "C:\\Temp", "ev_0006", "–"],
];

describe("a table with nothing to say in two of its columns", () => {
  it("lifts the constant out and drops the empty one", () => {
    const narrowed = withoutConstantColumns(columns, rows);

    expect(narrowed.columns).toEqual(["Kind", "Value"]);
    expect(narrowed.rows[0]).toEqual(["path", "C:\\Windows\\System32"]);
    expect(narrowed.constants).toEqual([{ column: "Evidence", value: "ev_0006" }]);
    expect(narrowed.empty).toEqual(["Notes"]);
  });

  it("keeps the first column even when every row repeats it", () => {
    // What kind every indicator is, is a fact about the run: forty `path` rows
    // under a tab called NETWORK is the finding.
    expect(withoutConstantColumns(columns, rows).columns[0]).toBe("Kind");
  });

  it("leaves a table whose columns all vary alone", () => {
    const varied = [
      ["a", "1", "ev_0001"],
      ["b", "2", "ev_0002"],
    ];
    const narrowed = withoutConstantColumns(["Kind", "Value", "Evidence"], varied);
    expect(narrowed.columns).toEqual(["Kind", "Value", "Evidence"]);
    expect(narrowed.rows).toEqual(varied);
  });

  it("leaves a one-row table alone, where every column is constant by accident", () => {
    const one = [["path", "C:\\Temp", "ev_0006", "–"]];
    expect(withoutConstantColumns(columns, one).columns).toEqual(columns);
  });
});
