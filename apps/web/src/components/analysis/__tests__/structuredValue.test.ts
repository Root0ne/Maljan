/**
 * A JSON value a tool returned is laid out for reading, never printed raw by
 * default, and nothing in it is dropped by the layout.
 */

import { describe, expect, it } from "vitest";

import { columnsOf, compactJson, jsonTokens, keyLabel, shapeOf } from "../structuredValue";

describe("the layout a value takes", () => {
  it("reads an object as fields, a list of objects as a table, a list of values as a list", () => {
    expect(shapeOf({ a: 1 })).toBe("object");
    expect(shapeOf([{ a: 1 }, { b: 2 }])).toBe("rows");
    expect(shapeOf(["a", 2, true])).toBe("list");
    expect(shapeOf([{ a: 1 }, "b"])).toBe("mixed");
    expect(shapeOf("x")).toBe("scalar");
    expect(shapeOf(0)).toBe("scalar");
    expect(shapeOf(false)).toBe("scalar");
  });

  it("says an empty value is empty", () => {
    for (const v of [null, undefined, "", [], {}]) expect(shapeOf(v)).toBe("empty");
  });
});

describe("a table of objects", () => {
  it("takes every key any row holds, in the order they first appear", () => {
    expect(columnsOf([{ pid: 1, name: "a" }, { name: "b", path: "c" }])).toEqual({
      columns: ["pid", "name", "path"],
      rest: [],
    });
  });

  it("keeps the keys past its width in one last column instead of dropping them", () => {
    const row = Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`k${i}`, i]));
    const { columns, rest } = columnsOf([row], 8);
    expect(columns).toHaveLength(7);
    expect([...columns, ...rest]).toEqual(Object.keys(row));
  });
});

describe("the words", () => {
  it("reads a key as a term, acronyms upper", () => {
    expect(keyLabel("file_size_bytes")).toBe("File size bytes");
    expect(keyLabel("threatLabel")).toBe("Threat label");
    expect(keyLabel("sha256")).toBe("SHA256");
    expect(keyLabel("_")).toBe("_");
  });

  it("cuts a value past the drawn depth to one line", () => {
    expect(compactJson({ a: [1, 2] })).toBe('{"a":[1,2]}');
    expect(compactJson("x".repeat(300), 10)).toBe(`${"x".repeat(9)}…`);
  });
});

describe("the raw view", () => {
  it("colours the printed JSON without changing a character of it", () => {
    const value = { name: "a \"q\"", n: -1.5e3, ok: true, none: null, list: [1, "two"] };
    const tokens = jsonTokens(value);
    expect(tokens.map((t) => t.text).join("")).toBe(JSON.stringify(value, null, 2));
    expect(tokens.find((t) => t.text === '"name"')?.kind).toBe("key");
    expect(tokens.find((t) => t.text === '"two"')?.kind).toBe("string");
    expect(tokens.find((t) => t.text === "-1500")?.kind).toBe("number");
    expect(tokens.find((t) => t.text === "true")?.kind).toBe("boolean");
    expect(tokens.find((t) => t.text === "null")?.kind).toBe("null");
  });
});
