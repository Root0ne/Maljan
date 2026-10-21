import { describe, expect, it } from "vitest";
import {
  ENRICHMENT_SOURCES_SPEC,
  REPORT_FORMATS_SPEC,
  SECRET_MASK,
  numberValue,
  otherFields,
  readRows,
  secretState,
  withSecret,
  withSecretCleared,
  withText,
  withEntry,
  withNewRow,
  withOption,
  withOtherFields,
  withoutRow,
  writeRows,
} from "../recordRows";

describe("reading a map or a list as rows", () => {
  it("reads a source map by key and a format list by position", () => {
    expect(readRows({ a: { label: "A" } }, "map")).toEqual([{ id: "a", entry: { label: "A" } }]);
    expect(readRows([{ name: "x" }, { name: "y" }], "list")?.map((r) => r.id)).toEqual(["0", "1"]);
  });

  it("reads an unset value as no rows and a value of another shape as none", () => {
    expect(readRows(null, "map")).toEqual([]);
    expect(readRows(undefined, "list")).toEqual([]);
    expect(readRows([], "map")).toBeNull();
    expect(readRows({}, "list")).toBeNull();
    expect(readRows({ a: 3 }, "map")).toBeNull();
    expect(readRows([1], "list")).toBeNull();
  });

  it("writes back the value it read", () => {
    const map = { a: { label: "A" }, b: { enabled: false } };
    const list = [{ name: "x", display_name: "X" }];
    expect(writeRows(readRows(map, "map")!, "map")).toEqual(map);
    expect(writeRows(readRows(list, "list")!, "list")).toEqual(list);
  });
});

describe("a field", () => {
  it("emptied keeps the key the stored record holds, as an empty string", () => {
    const stored = { server: "vt", label: "L" };
    expect(withText({ ...stored }, stored, "server", "")).toEqual({ server: "", label: "L" });
    expect(withText({ ...stored }, stored, "server", "x")).toEqual({ server: "x", label: "L" });
  });

  it("emptied is left out when it was added in this session or the row is new", () => {
    expect(withText({ display_name: "CAPE", name: "n" }, { name: "n" }, "display_name", "")).toEqual(
      { name: "n" },
    );
    expect(withText({ tool: "t" }, undefined, "tool", "")).toEqual({});
  });

  it("reads a number box as a number, or as nothing", () => {
    expect(numberValue("30")).toBe(30);
    expect(numberValue("")).toBeUndefined();
    expect(numberValue("abc")).toBeUndefined();
  });

  it("keeps the order of the options and the values it does not know", () => {
    expect(withOption(["ip"], ["domain", "ip"], "domain", true)).toEqual(["domain", "ip"]);
    expect(withOption(["ip", "url"], ["domain", "ip"], "ip", false)).toEqual(["url"]);
    expect(withOption(["ip"], ["domain", "ip"], "ip", false)).toBeUndefined();
  });
});

describe("a secret field", () => {
  const mask = { api_key: SECRET_MASK };

  it("reads as set while the mask is held, and an untouched record keeps it", () => {
    expect(secretState(mask, "api_key")).toBe("set");
    expect(withSecret(mask, "api_key", "")).toBe(mask);
    expect(writeRows(readRows({ a: mask }, "map")!, "map")).toEqual({ a: mask });
  });

  it("is staged only when the typed value is not empty, never built from the mask", () => {
    expect(withSecret(mask, "api_key", "abc")).toEqual({ api_key: "abc" });
    expect(secretState({ api_key: "abc" }, "api_key")).toBe("staged");
    expect(JSON.stringify(withSecret(mask, "api_key", "abc"))).not.toContain("*");
  });

  it("is cleared by null, and reads as not set when absent or empty", () => {
    expect(withSecretCleared(mask, "api_key")).toEqual({ api_key: null });
    expect(secretState({ api_key: null }, "api_key", mask)).toBe("cleared");
    // The API sends null for a source with no stored secret: that is not a clear.
    expect(secretState({ api_key: null }, "api_key", { api_key: null })).toBe("not-set");
    expect(secretState({ api_key: null }, "api_key", {})).toBe("not-set");
    expect(secretState({ api_key: null }, "api_key")).toBe("not-set");
    expect(secretState({}, "api_key")).toBe("not-set");
    expect(secretState({ api_key: "" }, "api_key")).toBe("not-set");
  });
});

describe("the fields the form does not name", () => {
  const entry = { label: "L", requests: { ip: { url: "https://x" } }, record: [] };

  it("stay in the JSON box and are not cut down", () => {
    expect(otherFields(entry, ENRICHMENT_SOURCES_SPEC)).toEqual({
      requests: { ip: { url: "https://x" } },
      record: [],
    });
    const read = withOtherFields(entry, ENRICHMENT_SOURCES_SPEC, '{"record": [1]}');
    expect(read).toEqual({ entry: { label: "L", record: [1] } });
  });

  it("refuse text that is not an object, or that names a field the form has", () => {
    expect(withOtherFields(entry, ENRICHMENT_SOURCES_SPEC, "[1]")).toEqual({
      error: "must be a JSON object",
    });
    expect(withOtherFields(entry, ENRICHMENT_SOURCES_SPEC, '{"label": "Z"}')).toHaveProperty("error");
    expect(withOtherFields(entry, ENRICHMENT_SOURCES_SPEC, "{")).toHaveProperty("error");
  });

  it("read an empty box as no other fields", () => {
    expect(withOtherFields(entry, ENRICHMENT_SOURCES_SPEC, "")).toEqual({ entry: { label: "L" } });
  });
});

describe("adding and removing rows", () => {
  it("needs a key no source has", () => {
    const rows = readRows({ a: {} }, "map")!;
    expect(withNewRow(rows, ENRICHMENT_SOURCES_SPEC, " ")).toHaveProperty("error");
    expect(withNewRow(rows, ENRICHMENT_SOURCES_SPEC, "a")).toHaveProperty("error");
    expect(withNewRow(rows, ENRICHMENT_SOURCES_SPEC, "b")).toEqual({
      rows: [
        { id: "a", entry: {} },
        { id: "b", entry: {} },
      ],
    });
  });

  it("appends a format without a key and renumbers after a removal", () => {
    const rows = readRows([{ name: "x" }, { name: "y" }], "list")!;
    const added = withNewRow(rows, REPORT_FORMATS_SPEC, "");
    expect("rows" in added && added.rows.map((r) => r.id)).toEqual(["0", "1", "2"]);
    const left = withoutRow(rows, REPORT_FORMATS_SPEC, "0");
    expect(left).toEqual([{ id: "0", entry: { name: "y" } }]);
  });

  it("replaces one row's record", () => {
    const rows = readRows([{ name: "x" }], "list")!;
    expect(writeRows(withEntry(rows, "0", { name: "x", display_name: "X" }), "list")).toEqual([
      { name: "x", display_name: "X" },
    ]);
  });
});

describe("the report format form", () => {
  it("has a field for the display name, as long as the model allows", () => {
    const field = REPORT_FORMATS_SPEC.fields.find((f) => f.name === "display_name");
    expect(field?.maxLength).toBe(64);
  });
});
