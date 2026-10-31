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
  return safeStringify(v);
}

/** What is printed for a value that cannot be printed at all. */
export const UNPRINTABLE = "(a value nested too deeply to print)";

/** `JSON.stringify` that never throws: a value it cannot print (a cycle, a
 *  nesting deeper than the engine's stack) is printed as `UNPRINTABLE` when
 *  it is an object or a list, and as `String(value)` otherwise. */
function safeStringify(v: unknown, indent?: number): string {
  try {
    return JSON.stringify(v, null, indent) ?? String(v);
  } catch {
    // An object's own String() is "[object Object]", which says nothing.
    if (typeof v === "object" && v !== null) return UNPRINTABLE;
    try {
      return String(v);
    } catch {
      return UNPRINTABLE;
    }
  }
}

/** A value past the drawn depth, as one line of JSON, cut at `max` characters. */
export function compactJson(v: unknown, max = 160): string {
  const text = typeof v === "string" ? v : safeStringify(v);
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** The deepest a parsed value is laid out at all; anything deeper is shown as its text. */
export const MAX_STRUCTURED_DEPTH = 64;

/**
 * How deeply `value` nests objects and lists, counted without recursion and
 * no further than `limit + 1`: a document nested thousands deep parses, but
 * printing or drawing it recursively would exhaust the stack.
 */
export function nestingDepth(value: unknown, limit = MAX_STRUCTURED_DEPTH): number {
  let deepest = 0;
  const stack: [unknown, number][] = [[value, 0]];
  while (stack.length > 0) {
    const [node, depth] = stack.pop()!;
    if (typeof node !== "object" || node === null) continue;
    const here = depth + 1;
    if (here > deepest) deepest = here;
    if (deepest > limit) return deepest;
    for (const child of Array.isArray(node) ? node : Object.values(node)) stack.push([child, here]);
  }
  return deepest;
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
  return jsonTextTokens(safeStringify(value, 2));
}

/**
 * JSON text exactly as it was written, split into tokens for colouring: the
 * raw view of a tool's output prints the output itself, never a re-printing
 * of what it parsed to (which would round a large integer or fold a repeated
 * key). The tokens joined are `text`, character for character.
 */
export function jsonTextTokens(text: string): JsonToken[] {
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

/** The most significant digits a JavaScript number holds exactly. */
const EXACT_DIGITS = 15;

/**
 * Whether a JSON number written as `token` survives being read as a
 * JavaScript number: finite, not underflowed to zero, and no more than 15
 * significant digits. Spelling is not a loss: `1.0`, `1e2` and `-0.50` read
 * back as the numbers they wrote.
 */
export function numberIsExact(token: string): boolean {
  const n = Number(token);
  if (!Number.isFinite(n)) return false;
  const m = /^-?(\d+)(?:\.(\d+))?(?:[eE][+-]?\d+)?$/.exec(token);
  if (!m) return false;
  const digits = `${m[1]}${m[2] ?? ""}`.replace(/^0+/, "").replace(/0+$/, "");
  if (digits.length === 0) return true; // a zero, however it is written
  if (n === 0) return false; // underflow: written non-zero, read as zero
  return digits.length <= EXACT_DIGITS;
}

/**
 * Whether laying out the value parsed from JSON `text` keeps everything the
 * text says, read off the text's own tokens: no number past what a number
 * holds exactly (`numberIsExact`), no key written twice in one object, and no
 * nesting deeper than `maxDepth`. How the text spells a string (`é` for
 * é, `\/` for /) and how it spaces its tokens are not losses; the raw view
 * prints the text as written anyway.
 */
export function losslessJson(text: string, maxDepth = MAX_STRUCTURED_DEPTH): boolean {
  /* One frame per open container: the keys seen so far in an object, null
   * for a list. */
  const stack: (Set<string> | null)[] = [];
  for (const token of jsonTextTokens(text)) {
    if (token.kind === "number" && !numberIsExact(token.text)) return false;
    if (token.kind === "key") {
      const keys = stack[stack.length - 1];
      if (!keys) continue;
      let key: string;
      try {
        key = JSON.parse(token.text) as string;
      } catch {
        return false;
      }
      if (keys.has(key)) return false;
      keys.add(key);
    }
    if (token.kind !== "punct") continue;
    for (const c of token.text) {
      if (c === "{" || c === "[") {
        stack.push(c === "{" ? new Set<string>() : null);
        if (stack.length > maxDepth) return false;
      } else if (c === "}" || c === "]") stack.pop();
    }
  }
  return true;
}
