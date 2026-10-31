/**
 * How a JSON value a tool or a model returned is laid out for reading
 * (`StructuredValue`), kept apart from the drawing.
 *
 * An object reads as a list of terms and their values, a list of objects as
 * a table whose columns are the keys its rows hold, a list of plain values as
 * a list, and a plain value inline. Nothing is dropped: a column past the
 * table's width, or a value nested past the depth the layout draws, is still
 * printed, as compact JSON, and the raw view prints the whole value.
 */

import { humaniseKey } from "@/lib/humanise";

export type ValueShape = "empty" | "scalar" | "object" | "rows" | "list" | "mixed";

export type JsonObject = Record<string, unknown>;

/** Whether `v` is a plain object (not null, not a list). */
export function isPlainObject(v: unknown): v is JsonObject {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Which layout a value takes. */
export function shapeOf(v: unknown): ValueShape {
  if (v === null || v === undefined || v === "") return "empty";
  if (Array.isArray(v)) {
    if (v.length === 0) return "empty";
    if (v.every(isPlainObject)) return "rows";
    if (v.every((x) => !isPlainObject(x) && !Array.isArray(x))) return "list";
    return "mixed";
  }
  if (isPlainObject(v)) return Object.keys(v).length === 0 ? "empty" : "object";
  return "scalar";
}

/** The most columns a table draws; the keys past it are kept in a last column. */
export const MAX_COLUMNS = 8;

/**
 * The columns of a table of `rows`: every key any row holds, in the order
 * they first appear, the first `MAX_COLUMNS` as columns and the rest named in
 * `rest`, which the table prints as one more column of compact JSON.
 */
export function columnsOf(rows: readonly JsonObject[], max = MAX_COLUMNS): { columns: string[]; rest: string[] } {
  const keys: string[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    for (const key of Object.keys(row)) {
      if (!seen.has(key)) {
        seen.add(key);
        keys.push(key);
      }
    }
  }
  return keys.length <= max ? { columns: keys, rest: [] } : { columns: keys.slice(0, max - 1), rest: keys.slice(max - 1) };
}

/**
 * A key as a reader's term (`humaniseKey`): `file_size_bytes` reads "File
 * size bytes", `threatLabel` "Threat label", `sha256` "SHA256". A key with no
 * words in it is kept as written.
 */
export function keyLabel(key: string): string {
  const k = String(key);
  return humaniseKey(k.replace(/([a-z0-9])([A-Z])/g, "$1_$2")) || k;
}

/** A plain value as text: a string as itself, anything else as JSON. */
export function scalarText(v: unknown): string {
  if (typeof v === "string") return v;
  if (v === undefined) return "";
  return JSON.stringify(v) ?? String(v);
}

/** A value past the drawn depth, as one line of JSON, cut at `max` characters. */
export function compactJson(v: unknown, max = 160): string {
  const text = typeof v === "string" ? v : (JSON.stringify(v) ?? String(v));
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

export type JsonTokenKind = "key" | "string" | "number" | "boolean" | "null" | "punct" | "space";

export interface JsonToken {
  kind: JsonTokenKind;
  text: string;
}

const JSON_TOKEN =
  /("(?:\\.|[^"\\])*")(\s*:)?|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false)\b|\b(null)\b|([{}[\],:])|(\s+)/g;

/**
 * Pretty-printed JSON split into tokens for the raw view's colouring. The
 * tokens joined are the printed text, character for character.
 */
export function jsonTokens(value: unknown): JsonToken[] {
  const text = JSON.stringify(value, null, 2) ?? String(value);
  const out: JsonToken[] = [];
  let at = 0;
  for (const m of text.matchAll(JSON_TOKEN)) {
    const start = m.index ?? 0;
    if (start > at) out.push({ kind: "punct", text: text.slice(at, start) });
    if (m[1] !== undefined) {
      out.push({ kind: m[2] ? "key" : "string", text: m[1] });
      if (m[2]) out.push({ kind: "punct", text: m[2] });
    } else if (m[3] !== undefined) out.push({ kind: "number", text: m[3] });
    else if (m[4] !== undefined) out.push({ kind: "boolean", text: m[4] });
    else if (m[5] !== undefined) out.push({ kind: "null", text: m[5] });
    else if (m[6] !== undefined) out.push({ kind: "punct", text: m[6] });
    else out.push({ kind: "space", text: m[7] ?? "" });
    at = start + m[0].length;
  }
  if (at < text.length) out.push({ kind: "punct", text: text.slice(at) });
  return out;
}
