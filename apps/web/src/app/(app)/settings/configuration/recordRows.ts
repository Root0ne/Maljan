/* The rows of a settings value that is a map of records (`api.enrichment_sources`,
 * keyed by source) or a list of records (`sandbox.report_formats`).
 *
 * A row's named fields are drawn as controls; every other key of the record
 * stays in one JSON box per row, so a record is never cut down to what the
 * form names. These records are overlays on what ships: a key the stored
 * record holds is never deleted by emptying its box (a text field then keeps
 * `""`, and an empty `server` still says "no server"); only a field added in
 * this session is left out again when emptied. A number box emptied is left
 * out, since an empty string is no number. */

export type RowsShape = "map" | "list";

export type FieldKind = "text" | "bool" | "number" | "kinds";

export interface RowField {
  name: string;
  label: string;
  kind: FieldKind;
  hint?: string;
  /** The choices of a `kinds` field. */
  options?: string[];
  /** The value a bool field holds when the record does not carry it. */
  fallback?: boolean;
  maxLength?: number;
  /** Drawn as a password box; the value is the API's mask, kept as it is. */
  secret?: boolean;
}

export interface RowsSpec {
  shape: RowsShape;
  /** What one row is called ("source", "format"). */
  noun: string;
  fields: RowField[];
}

export type Fields = Record<string, unknown>;

export interface Row {
  /** The key of a map row; the position of a list row. */
  id: string;
  entry: Fields;
}

function isFields(value: unknown): value is Fields {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The rows of `value`, or `null` when it is not the shape (the JSON view then stays the only one). */
export function readRows(value: unknown, shape: RowsShape): Row[] | null {
  if (value === undefined || value === null) return [];
  if (shape === "map") {
    if (!isFields(value)) return null;
    const rows: Row[] = [];
    for (const [id, entry] of Object.entries(value)) {
      if (!isFields(entry)) return null;
      rows.push({ id, entry });
    }
    return rows;
  }
  if (!Array.isArray(value)) return null;
  const rows: Row[] = [];
  for (let i = 0; i < value.length; i += 1) {
    const entry: unknown = value[i];
    if (!isFields(entry)) return null;
    rows.push({ id: String(i), entry });
  }
  return rows;
}

/** The value the rows make. */
export function writeRows(rows: Row[], shape: RowsShape): unknown {
  if (shape === "list") return rows.map((row) => row.entry);
  return Object.fromEntries(rows.map((row) => [row.id, row.entry]));
}

/** `entry` with `name` set to `value`, or without it when `value` is `undefined`. */
export function withField(entry: Fields, name: string, value: unknown): Fields {
  const next = { ...entry };
  if (value === undefined) delete next[name];
  else next[name] = value;
  return next;
}

/** `entry` with text field `name` set to `raw`. Emptied, the field stays as `""` when
 *  the stored record holds it, and is left out when it was added in this session. */
export function withText(
  entry: Fields,
  stored: Fields | undefined,
  name: string,
  raw: string,
): Fields {
  if (raw !== "") return withField(entry, name, raw);
  return withField(entry, name, stored !== undefined && name in stored ? "" : undefined);
}

/** The mask the API sends for a stored secret; sent back, it means "keep the stored one". */
export const SECRET_MASK = "**********";

export type SecretState = "set" | "not-set" | "staged" | "cleared";

/** What a secret field of a record holds: the mask is a stored value, empty or absent
 *  is none, anything else was typed. `null` is a clear only where the saved record
 *  held a secret (the mask); the API itself sends `null` for a source with none. */
export function secretState(entry: Fields, name: string, stored?: Fields): SecretState {
  const held = entry[name];
  if (held === null) return stored?.[name] === SECRET_MASK ? "cleared" : "not-set";
  if (typeof held !== "string" || held === "") return "not-set";
  return held === SECRET_MASK ? "set" : "staged";
}

/** `entry` with a typed secret staged. An empty value is not one, and never replaces what is held. */
export function withSecret(entry: Fields, name: string, typed: string): Fields {
  return typed === "" ? entry : withField(entry, name, typed);
}

/** `entry` with the secret's removal staged: `null`, which the API reads as delete the row. */
export function withSecretCleared(entry: Fields, name: string): Fields {
  return withField(entry, name, null);
}

/** What a number box holds as a field value: nothing when empty or not a number. */
export function numberValue(raw: string): number | undefined {
  if (raw.trim() === "") return undefined;
  const n = Number(raw);
  return Number.isFinite(n) ? n : undefined;
}

/** `list` with `option` ticked or not, in the order of `options`, values it does not know kept last. */
export function withOption(
  list: unknown,
  options: string[],
  option: string,
  on: boolean,
): string[] | undefined {
  const held = new Set(
    Array.isArray(list) ? list.filter((v): v is string => typeof v === "string") : [],
  );
  if (on) held.add(option);
  else held.delete(option);
  const known = options.filter((o) => held.has(o));
  const extra = [...held].filter((o) => !options.includes(o));
  const out = [...known, ...extra];
  return out.length > 0 ? out : undefined;
}

/** The part of a record the form's named fields do not draw. */
export function otherFields(entry: Fields, spec: RowsSpec): Fields {
  const named = new Set(spec.fields.map((f) => f.name));
  return Object.fromEntries(Object.entries(entry).filter(([name]) => !named.has(name)));
}

/** `entry` with its unnamed part replaced by what `text` reads as, or the reason it does not. */
export function withOtherFields(
  entry: Fields,
  spec: RowsSpec,
  text: string,
): { entry: Fields } | { error: string } {
  let read: unknown;
  try {
    read = JSON.parse(text.trim() === "" ? "{}" : text);
  } catch (err) {
    return { error: err instanceof Error ? err.message : "not JSON" };
  }
  if (!isFields(read)) return { error: "must be a JSON object" };
  const named = new Set(spec.fields.map((f) => f.name));
  const clash = Object.keys(read).filter((name) => named.has(name));
  if (clash.length > 0) return { error: `${clash.join(", ")}: has its own control above` };
  const kept = Object.fromEntries(Object.entries(entry).filter(([name]) => named.has(name)));
  return { entry: { ...kept, ...read } };
}

/** The rows with a new one, or why it cannot be added. A map row needs a key no row has. */
export function withNewRow(
  rows: Row[],
  spec: RowsSpec,
  key: string,
): { rows: Row[] } | { error: string } {
  if (spec.shape === "list") return { rows: [...rows, { id: String(rows.length), entry: {} }] };
  const id = key.trim();
  if (id === "") return { error: `Name the ${spec.noun}` };
  if (rows.some((row) => row.id === id)) {
    return { error: `A ${spec.noun} named ${id} is already here` };
  }
  return { rows: [...rows, { id, entry: {} }] };
}

/** The rows without row `id`; a list's later rows move up. */
export function withoutRow(rows: Row[], spec: RowsSpec, id: string): Row[] {
  const kept = rows.filter((row) => row.id !== id);
  return spec.shape === "list" ? kept.map((row, i) => ({ ...row, id: String(i) })) : kept;
}

/** The rows with row `id` replaced by `entry`. */
export function withEntry(rows: Row[], id: string, entry: Fields): Row[] {
  return rows.map((row) => (row.id === id ? { ...row, entry } : row));
}

export const ENRICHMENT_SOURCES_SPEC: RowsSpec = {
  shape: "map",
  noun: "source",
  fields: [
    { name: "label", label: "Label", kind: "text" },
    { name: "enabled", label: "Enabled", kind: "bool", fallback: true },
    { name: "kinds", label: "Asks about", kind: "kinds", options: ["domain", "ip"] },
    { name: "order", label: "Order", kind: "number", hint: "Sources are asked lowest first." },
    {
      name: "server",
      label: "Tool server",
      kind: "text",
      hint: "The key of a reputation tool server.",
    },
    {
      name: "tool",
      label: "Tool",
      kind: "text",
      hint: "Empty: the server's indicator lookup for each kind, read from its declarations.",
    },
    {
      name: "credential",
      label: "Credential setting",
      kind: "text",
      hint: "A secret setting of the enrichment group, such as one a shipped source reads.",
    },
    {
      name: "api_key",
      label: "Own API key",
      kind: "text",
      secret: true,
      hint: "Stored encrypted and shown masked; leave the mask to keep the stored key.",
    },
    { name: "timeout_seconds", label: "Timeout (s)", kind: "number" },
    { name: "rate_limit_seconds", label: "Pause between asks (s)", kind: "number" },
    { name: "answer_root", label: "Answer root", kind: "text" },
    { name: "record_source", label: "Record source name", kind: "text" },
    { name: "age_from", label: "Age from field", kind: "text" },
  ],
};

export const REPORT_FORMATS_SPEC: RowsSpec = {
  shape: "list",
  noun: "format",
  fields: [
    { name: "name", label: "Name", kind: "text", maxLength: 32 },
    {
      name: "display_name",
      label: "Display name",
      kind: "text",
      maxLength: 64,
      hint: "What published text calls the sandbox whose report this is; empty, the format's name.",
    },
    {
      name: "reader",
      label: "Reader",
      kind: "text",
      hint: "cape2, cuckoo, triage, generic, or empty.",
    },
  ],
};
