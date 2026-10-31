"use client";

import { Component, useState, type ReactNode } from "react";
import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import {
  MAX_STRUCTURED_DEPTH,
  columnsOf,
  compactJson,
  isPlainObject,
  jsonTextTokens,
  jsonTokens,
  keyLabel,
  nestingDepth,
  scalarText,
  shapeOf,
  type JsonObject,
  type JsonToken,
  type JsonTokenKind,
} from "./structuredValue";

/**
 * A JSON value a tool or a model returned, laid out for reading
 * (`structuredValue`): an object as terms and values, a list of objects as a
 * table that scrolls sideways in its own named region, a list of plain
 * values as a list, a plain value inline. Past `MAX_DEPTH` a nested value is
 * printed as one line of JSON; a list, a table or an object's fields show
 * their first `FIRST_ROWS` and offer the rest. "View raw" swaps the layout
 * for coloured JSON; it is never the default. Given `source`, the text the
 * value was parsed from, the raw view prints that text itself, so it is the
 * evidence exactly as it arrived.
 *
 * A value nested deeper than `MAX_STRUCTURED_DEPTH` is not laid out, and a
 * drawing that fails anyway falls back to the plain text: one odd document
 * never takes the page down with it.
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

export default function StructuredValue({ value, name, source }: { value: unknown; name: string; source?: string }) {
  return (
    <StructuredBoundary value={value} source={source}>
      <StructuredBody value={value} name={name} source={source} />
    </StructuredBoundary>
  );
}

/** What is shown when a value cannot be laid out: its text, as it is. */
function PlainText({ value, source }: { value: unknown; source?: string }) {
  return (
    <pre className="max-w-full overflow-x-auto whitespace-pre-wrap break-all rounded border border-border-light bg-bg-deep px-3 py-2 font-mono text-xs leading-5 text-text-secondary">
      {source ?? compactJson(value, 50_000)}
    </pre>
  );
}

class StructuredBoundary extends Component<
  { value: unknown; source?: string; children: ReactNode },
  { failed: boolean }
> {
  state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  componentDidUpdate(prev: { value: unknown }) {
    if (this.state.failed && prev.value !== this.props.value) this.setState({ failed: false });
  }

  render() {
    return this.state.failed ? <PlainText value={this.props.value} source={this.props.source} /> : this.props.children;
  }
}

function StructuredBody({ value, name, source }: { value: unknown; name: string; source?: string }) {
  const [raw, setRaw] = useState(false);
  const shape = shapeOf(value);
  if (nestingDepth(value) > MAX_STRUCTURED_DEPTH) return <PlainText value={value} source={source} />;
  return (
    <div className="@container min-w-0 space-y-2">
      {shape !== "scalar" && shape !== "empty" && (
        <div className="flex justify-end">
          <button
            type="button"
            aria-pressed={raw}
            onClick={() => setRaw((v) => !v)}
            /* `relative`, so the screen-reader words stay inside the box that
             * scrolls; placed against a far ancestor they widened the page. */
            className="relative rounded px-1 text-[11px] text-accent-strong hover:underline"
          >
            {raw ? "View as fields" : "View raw"}
            <span className="sr-only"> of {name}</span>
          </button>
        </div>
      )}
      {raw ? <RawJson value={value} name={name} source={source} /> : <ValueView value={value} name={name} depth={0} />}
    </div>
  );
}

/**
 * One value in a table cell or a definition: a plain value inline, a nested
 * one laid out a level deep and then as one line of JSON, never a dump.
 */
export function StructuredCell({ value, name }: { value: unknown; name: string }) {
  return <ValueView value={value} name={name} depth={1} />;
}

/** The value as coloured JSON: `source` as written when given, else the value pretty-printed. */
export function RawJson({ value, name, source }: { value: unknown; name: string; source?: string }) {
  const tokens: JsonToken[] = source !== undefined ? jsonTextTokens(source) : jsonTokens(value);
  return (
    <pre
      {...scrollRegion(`${name} raw JSON`)}
      className={`max-w-full overflow-x-auto rounded border border-border-light bg-bg-deep px-3 py-2 font-mono text-xs leading-5 ${SCROLL_REGION_FOCUS}`}
    >
      {tokens.map((t, i) =>
        t.kind === "space" ? t.text : (
          <span key={i} className={TOKEN_CLASS[t.kind]}>
            {t.text}
          </span>
        ),
      )}
    </pre>
  );
}

/** The first `FIRST_ROWS` of a long list, and the control that shows the rest. */
function useFirst<T>(items: readonly T[]): { shown: readonly T[]; more: ReactNode } {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, FIRST_ROWS);
  const more =
    items.length > FIRST_ROWS ? (
      <button type="button" onClick={() => setAll((v) => !v)} className="text-[11px] text-accent-strong hover:underline">
        {all ? `Show the first ${FIRST_ROWS}` : `Show all ${items.length}`}
      </button>
    ) : null;
  return { shown, more };
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
  return <List items={value as unknown[]} name={name} depth={depth} />;
}

function List({ items, name, depth }: { items: unknown[]; name: string; depth: number }) {
  const { shown, more } = useFirst(items);
  return (
    <div className="space-y-1">
      <ul className="list-disc space-y-0.5 pl-5">
        {shown.map((item, i) => (
          <li key={i} className="min-w-0 [overflow-wrap:anywhere]">
            <ValueView value={item} name={`${name}, item ${i + 1}`} depth={depth + 1} />
          </li>
        ))}
      </ul>
      {more}
    </div>
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
  const { shown, more } = useFirst(Object.entries(value));
  return (
    <div className="space-y-1">
      <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 text-xs @md:grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)]">
        {shown.map(([key, v]) => (
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
      {more}
    </div>
  );
}

function Rows({ rows, name, depth }: { rows: JsonObject[]; name: string; depth: number }) {
  const { shown, more } = useFirst(rows);
  const { columns, rest } = columnsOf(rows);
  return (
    <div className="space-y-1">
      <div
        {...scrollRegion(name)}
        className={`max-w-full overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}
      >
        <table className="w-max min-w-full text-xs">
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
                  <td key={c} className="min-w-[7rem] max-w-[28rem] px-2 py-1.5 text-text-primary [overflow-wrap:anywhere]">
                    {/* Own keys only: a column named `constructor` or `toString`
                        is the row's field, never a property every object inherits. */}
                    {Object.hasOwn(row, c) ? (
                      <ValueView value={row[c]} name={`${name}, row ${i + 1}, ${keyLabel(c)}`} depth={depth + 2} />
                    ) : null}
                  </td>
                ))}
                {rest.length > 0 && (
                  <td className="max-w-[28rem] px-2 py-1.5 font-mono text-text-secondary [overflow-wrap:anywhere]">
                    {compactJson(Object.fromEntries(rest.filter((k) => Object.hasOwn(row, k)).map((k) => [k, row[k]])), 400)}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {more}
    </div>
  );
}
