"use client";

import { useState, type ReactNode } from "react";
import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import {
  columnsOf,
  compactJson,
  isPlainObject,
  jsonTokens,
  keyLabel,
  scalarText,
  shapeOf,
  type JsonObject,
  type JsonTokenKind,
} from "./structuredValue";

/**
 * A JSON value a tool or a model returned, laid out for reading
 * (`structuredValue`): an object as terms and values, a list of objects as a
 * table that scrolls sideways in its own named region, a list of plain
 * values as a list, a plain value inline. Past `MAX_DEPTH` a nested value is
 * printed as one line of JSON. "View raw" swaps the layout for the whole
 * value as coloured, pretty-printed JSON; it is never the default.
 *
 * `name` names the block's scroll regions; it must be unique on the page
 * (the evidence entry's id, the object's id).
 */

const MAX_DEPTH = 3;
const FIRST_ROWS = 50;

const TOKEN_CLASS: Record<JsonTokenKind, string> = {
  key: "text-status-purple",
  string: "text-status-blue",
  number: "text-status-green",
  boolean: "text-status-orange",
  null: "text-text-muted",
  punct: "text-text-muted",
  space: "",
};

export default function StructuredValue({ value, name }: { value: unknown; name: string }) {
  const [raw, setRaw] = useState(false);
  const shape = shapeOf(value);
  return (
    <div className="min-w-0 space-y-2">
      {shape !== "scalar" && shape !== "empty" && (
        <div className="flex justify-end">
          <button
            type="button"
            aria-pressed={raw}
            onClick={() => setRaw((v) => !v)}
            className="rounded px-1 text-[11px] text-accent-strong hover:underline"
          >
            {raw ? "View as fields" : "View raw"}
            <span className="sr-only"> of {name}</span>
          </button>
        </div>
      )}
      {raw ? <RawJson value={value} name={name} /> : <ValueView value={value} name={name} depth={0} />}
    </div>
  );
}

/** The whole value as pretty-printed JSON, coloured by token. */
export function RawJson({ value, name }: { value: unknown; name: string }) {
  return (
    <pre
      {...scrollRegion(`${name} raw JSON`)}
      className={`max-w-full overflow-x-auto rounded border border-border-light bg-bg-deep px-3 py-2 font-mono text-xs leading-5 ${SCROLL_REGION_FOCUS}`}
    >
      {jsonTokens(value).map((t, i) =>
        t.kind === "space" ? t.text : (
          <span key={i} className={TOKEN_CLASS[t.kind]}>
            {t.text}
          </span>
        ),
      )}
    </pre>
  );
}

function ValueView({ value, name, depth }: { value: unknown; name: string; depth: number }): ReactNode {
  const shape = shapeOf(value);
  if (shape === "empty") return <span className="text-text-muted">{emptyWord(value)}</span>;
  if (shape === "scalar") return <Scalar value={value} />;
  if (depth >= MAX_DEPTH) {
    return <code className="font-mono text-xs text-text-secondary [overflow-wrap:anywhere]">{compactJson(value)}</code>;
  }
  if (shape === "object") return <Fields value={value as JsonObject} name={name} depth={depth} />;
  if (shape === "rows") return <Rows rows={value as JsonObject[]} name={name} depth={depth} />;
  const items = value as unknown[];
  return (
    <ul className="list-disc space-y-0.5 pl-5">
      {items.map((item, i) => (
        <li key={i} className="min-w-0 [overflow-wrap:anywhere]">
          <ValueView value={item} name={`${name}, item ${i + 1}`} depth={depth + 1} />
        </li>
      ))}
    </ul>
  );
}

function emptyWord(value: unknown): string {
  if (Array.isArray(value)) return "None";
  if (isPlainObject(value)) return "Nothing recorded";
  return "Not stated";
}

function Scalar({ value }: { value: unknown }) {
  const text = scalarText(value);
  if (typeof value === "boolean") return <span>{value ? "Yes" : "No"}</span>;
  if (typeof value === "number") return <span className="tabular-nums">{text}</span>;
  // A long or multi-line text keeps its lines; a short one sits inline.
  if (text.includes("\n") || text.length > 160) {
    return <span className="block whitespace-pre-wrap [overflow-wrap:anywhere]">{text}</span>;
  }
  return <span className="[overflow-wrap:anywhere]">{text}</span>;
}

function Fields({ value, name, depth }: { value: JsonObject; name: string; depth: number }) {
  return (
    <dl className="grid grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-xs">
      {Object.entries(value).map(([key, v]) => (
        <div key={key} className="contents">
          <dt className="text-text-muted [overflow-wrap:anywhere]" title={key}>
            {keyLabel(key)}
          </dt>
          <dd className="min-w-0 text-text-primary">
            <ValueView value={v} name={`${name}, ${keyLabel(key)}`} depth={depth + 1} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function Rows({ rows, name, depth }: { rows: JsonObject[]; name: string; depth: number }) {
  const [all, setAll] = useState(false);
  const { columns, rest } = columnsOf(rows);
  const shown = all ? rows : rows.slice(0, FIRST_ROWS);
  return (
    <div className="space-y-1">
      <div
        {...scrollRegion(name)}
        className={`max-w-full overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}
      >
        <table className="w-full text-xs">
          <thead className="bg-bg-deep">
            <tr className="border-b border-border-light text-left">
              {columns.map((c) => (
                <th key={c} scope="col" className="whitespace-nowrap px-2 py-1.5 font-medium text-text-muted" title={c}>
                  {keyLabel(c)}
                </th>
              ))}
              {rest.length > 0 && (
                <th scope="col" className="whitespace-nowrap px-2 py-1.5 font-medium text-text-muted">
                  Other fields
                </th>
              )}
            </tr>
          </thead>
          <tbody>
            {shown.map((row, i) => (
              <tr key={i} className="border-b border-border-light align-top last:border-b-0">
                {columns.map((c) => (
                  <td key={c} className="max-w-[28rem] px-2 py-1.5 text-text-primary [overflow-wrap:anywhere]">
                    {c in row ? (
                      <ValueView value={row[c]} name={`${name}, row ${i + 1}, ${keyLabel(c)}`} depth={depth + 2} />
                    ) : null}
                  </td>
                ))}
                {rest.length > 0 && (
                  <td className="max-w-[28rem] px-2 py-1.5 font-mono text-text-secondary [overflow-wrap:anywhere]">
                    {compactJson(Object.fromEntries(rest.filter((k) => k in row).map((k) => [k, row[k]])), 400)}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > FIRST_ROWS && (
        <button type="button" onClick={() => setAll((v) => !v)} className="text-[11px] text-accent-strong hover:underline">
          {all ? `Show the first ${FIRST_ROWS}` : `Show all ${rows.length} rows`}
        </button>
      )}
    </div>
  );
}
