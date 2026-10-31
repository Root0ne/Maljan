/**
 * A JSON value a tool returned is laid out for reading, never printed raw by
 * default, and nothing in it is dropped by the layout.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import StructuredValue from "../StructuredValue";
import {
  MAX_STRUCTURED_DEPTH,
  columnsOf,
  compactJson,
  jsonTextTokens,
  jsonTokens,
  keyLabel,
  nestingDepth,
  shapeOf,
} from "../structuredValue";

describe("a document that cannot be printed or drawn safely", () => {
  const deep = (n: number) => {
    let v: unknown = 1;
    for (let i = 0; i < n; i++) v = [v];
    return v;
  };

  it("measures nesting without recursion, and stops counting past the limit", () => {
    expect(nestingDepth({ a: [1, { b: 2 }] })).toBe(3);
    expect(nestingDepth("x")).toBe(0);
    expect(nestingDepth(deep(10_000))).toBe(MAX_STRUCTURED_DEPTH + 1);
  });

  it("prints a value nested past the engine's stack as text instead of throwing", () => {
    const value = deep(20_000);
    expect(() => compactJson(value)).not.toThrow();
    expect(() => jsonTokens(value)).not.toThrow();
  });

  it("draws a deeply nested value as its text, never laid out", () => {
    const html = renderToStaticMarkup(createElement(StructuredValue, { value: deep(200), name: "Deep" }));
    expect(html).toContain("<pre");
    expect(html).not.toContain("View raw");
  });
});

describe("the raw view of a tool's own text", () => {
  it("prints the text as written, never a re-printing of the parsed value", () => {
    const source = '{"n": 12345678901234567890, "n": 2}';
    expect(jsonTextTokens(source).map((t) => t.text).join("")).toBe(source);
  });
});

describe("a key that names an inherited property", () => {
  it("is drawn as the row's own field, and a row without it draws nothing there", () => {
    const rows: Record<string, unknown>[] = [{ constructor: "own", toString: "also own" }, { name: "x" }];
    const html = renderToStaticMarkup(createElement(StructuredValue, { value: rows, name: "Proto" }));
    expect(html).toContain("also own");
    expect(html).not.toContain("function");
    expect(html).not.toContain("native code");
  });
});

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
