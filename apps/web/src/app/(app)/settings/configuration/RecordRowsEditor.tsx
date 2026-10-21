"use client";

import { useEffect, useId, useState, type ReactNode } from "react";
import type { CatalogEntry, SettingValue } from "@/types/settings";
import { unreadBoxNote } from "./boxReading";
import SecretField from "./SecretField";
import { useOptionalSettingsContext } from "./SettingsContext";
import {
  numberValue,
  otherFields,
  readRows,
  secretState,
  withSecret,
  withSecretCleared,
  withText,
  withEntry,
  withField,
  withNewRow,
  withOption,
  withOtherFields,
  withoutRow,
  writeRows,
  type Fields,
  type Row,
  type RowField,
  type RowsSpec,
} from "./recordRows";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1 text-sm text-text-primary focus:outline-none focus:border-accent disabled:opacity-50 disabled:cursor-not-allowed";
const button =
  "h-6 rounded border border-border px-2 text-[11px] text-text-secondary hover:text-text-primary disabled:opacity-50";

function FieldControl({
  field,
  entry,
  stored,
  rowId,
  editable,
  onChange,
}: {
  field: RowField;
  entry: Fields;
  /** The record as saved, when this row is saved: a key it holds is not deleted by emptying. */
  stored: Fields | undefined;
  rowId: string;
  editable: boolean;
  onChange: (next: Fields) => void;
}) {
  const id = useId();
  const held = entry[field.name];
  const label = `${field.label} of ${rowId}`;
  if (field.kind === "bool") {
    return (
      <label className="flex items-center gap-2 text-[11px] text-text-secondary">
        <input
          type="checkbox"
          aria-label={label}
          disabled={!editable}
          checked={typeof held === "boolean" ? held : (field.fallback ?? false)}
          onChange={(e) => onChange(withField(entry, field.name, e.target.checked))}
        />
        {field.label}
      </label>
    );
  }
  if (field.kind === "kinds") {
    const options = field.options ?? [];
    return (
      <fieldset className="text-[11px] text-text-secondary">
        <legend className="text-text-muted">{field.label}</legend>
        <div className="flex gap-3">
          {options.map((option) => (
            <label key={option} className="flex items-center gap-1.5">
              <input
                type="checkbox"
                aria-label={`${field.label} ${option} of ${rowId}`}
                disabled={!editable}
                checked={Array.isArray(held) && held.includes(option)}
                onChange={(e) =>
                  onChange(
                    withField(entry, field.name, withOption(held, options, option, e.target.checked)),
                  )
                }
              />
              {option}
            </label>
          ))}
        </div>
      </fieldset>
    );
  }
  if (field.secret) {
    // The shared secret control: the value never fills the box, the mask stays
    // in the record while untouched, a typed value is staged only when it is
    // not empty, and Clear stages `null`.
    return (
      <div>
        <span className="block text-[11px] text-text-muted">{field.label}</span>
        <div className="py-1">
          <SecretField
            id={id}
            name={`${rowId}-${field.name}`}
            title={label}
            status={secretState(entry, field.name, stored)}
            editable={editable}
            onStage={(typed) => onChange(withSecret(entry, field.name, typed))}
            onClear={() => onChange(withSecretCleared(entry, field.name))}
            onCancel={() => undefined}
          />
        </div>
        {field.hint && <p className="text-[10px] text-text-muted mt-0.5">{field.hint}</p>}
      </div>
    );
  }
  return (
    <div>
      <label htmlFor={id} className="block text-[11px] text-text-muted">
        {field.label}
      </label>
      {field.kind === "number" ? (
        <NumberBox
          id={id}
          label={label}
          held={held}
          editable={editable}
          onValue={(n) => onChange(withField(entry, field.name, n))}
        />
      ) : (
        <input
          id={id}
          aria-label={label}
          type="text"
          maxLength={field.maxLength}
          disabled={!editable}
          className={input}
          value={held === undefined || held === null ? "" : String(held)}
          onChange={(e) => onChange(withText(entry, stored, field.name, e.target.value))}
        />
      )}
      {field.hint && <p className="text-[10px] text-text-muted mt-0.5">{field.hint}</p>}
    </div>
  );
}

/** A number box whose text is its own while typing, so "-", "1." and "1e" are not
 *  reset by the record they do not yet read as. It follows the record only when
 *  the record's value moves to something the text does not read as (a discard). */
function NumberBox({
  id,
  label,
  held,
  editable,
  onValue,
}: {
  id: string;
  label: string;
  held: unknown;
  editable: boolean;
  onValue: (n: number | undefined) => void;
}) {
  const value = typeof held === "number" ? held : undefined;
  const [text, setText] = useState(() => (value === undefined ? "" : String(value)));
  const [seen, setSeen] = useState(value);
  if (value !== seen) {
    setSeen(value);
    if (numberValue(text) !== value) setText(value === undefined ? "" : String(value));
  }
  return (
    <input
      id={id}
      aria-label={label}
      type="number"
      disabled={!editable}
      className={`${input} font-mono`}
      value={text}
      onChange={(e) => {
        setText(e.target.value);
        onValue(numberValue(e.target.value));
      }}
    />
  );
}

/** The part of a record the named fields leave out, as one JSON box. A text that
 *  does not read holds Apply, as every JSON box on this page does. */
function OtherFieldsBox({
  entry,
  spec,
  title,
  editable,
  onChange,
}: {
  entry: Fields;
  spec: RowsSpec;
  title: string;
  editable: boolean;
  onChange: (next: Fields) => void;
}) {
  const hold = useId();
  const note = useOptionalSettingsContext()?.noteUnreadInput;
  const [text, setText] = useState(() => JSON.stringify(otherFields(entry, spec), null, 2));
  const [bad, setBad] = useState<string | null>(null);
  // The hold ends with the box: a removed card, a discard or the switch to the
  // JSON view must not leave Apply held by text nobody can see any more.
  useEffect(() => () => note?.(hold, null), [hold, note]);
  return (
    <div>
      <label className="block text-[11px] text-text-muted">Other fields (JSON)</label>
      <textarea
        aria-label={`Other fields of ${title}`}
        aria-invalid={bad ? true : undefined}
        className={`${input} font-mono text-[11px]`}
        rows={Math.min(10, Math.max(3, text.split("\n").length))}
        disabled={!editable}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          const read = withOtherFields(entry, spec, e.target.value);
          if ("error" in read) {
            setBad(read.error);
            note?.(hold, unreadBoxNote(`${title}, other fields`, read.error));
            return;
          }
          setBad(null);
          note?.(hold, null);
          onChange(read.entry);
        }}
      />
      {bad && (
        <div role="alert" className="text-[11px] text-status-red mt-1">
          Invalid: {bad}
        </div>
      )}
    </div>
  );
}

/**
 * A map or list of records drawn as one card per record, its named fields as
 * controls and the rest as JSON, with the JSON view of the whole value one
 * click away. A value that is not the shape (a hand-typed scalar, say) opens
 * the JSON view alone.
 */
export default function RecordRowsEditor({
  entry,
  current,
  staged,
  spec,
  onChange,
  jsonView,
}: {
  entry: CatalogEntry;
  current?: SettingValue;
  staged: unknown;
  spec: RowsSpec;
  onChange: (value: unknown) => void;
  /** The ordinary JSON widget of the same value, drawn in place of the cards. */
  jsonView: ReactNode;
}) {
  const value = staged !== undefined ? staged : (current?.value ?? entry.default);
  const rows = readRows(value, spec.shape);
  const saved = readRows(current?.value ?? entry.default, spec.shape) ?? [];
  const [asJson, setAsJson] = useState(false);
  const [newKey, setNewKey] = useState("");
  const [addError, setAddError] = useState<string | null>(null);
  // The JSON boxes keep their own text while typed in; a discard or a removal
  // that moves rows under them starts them again from the value.
  const generation = useOptionalSettingsContext()?.discardGeneration ?? 0;
  const [removals, setRemovals] = useState(0);
  const showJson = asJson || rows === null;
  const stage = (next: Row[]) => onChange(writeRows(next, spec.shape));

  return (
    <div className="space-y-2" data-record-rows={showJson ? "json" : "cards"}>
      {rows !== null && (
        <button type="button" className={button} onClick={() => setAsJson(!asJson)}>
          {showJson ? "Edit as a form" : "Edit as JSON"}
        </button>
      )}
      {showJson ? (
        jsonView
      ) : (
        <>
          {rows.length === 0 && (
            <p className="text-[11px] text-text-muted">No {spec.noun} declared here.</p>
          )}
          {rows.map((row) => {
            const title = spec.shape === "map" ? row.id : `${spec.noun} ${Number(row.id) + 1}`;
            const set = (next: Fields) => stage(withEntry(rows, row.id, next));
            return (
              <section
                key={`${generation}:${removals}:${row.id}`}
                data-record-row={row.id}
                className="border border-border rounded px-3 py-2 space-y-2"
              >
                <div className="flex items-center gap-2">
                  <h4 className="text-xs font-mono text-text-primary">{title}</h4>
                  <button
                    type="button"
                    className={`${button} ml-auto`}
                    disabled={!entry.editable}
                    onClick={() => {
                      setRemovals(removals + 1);
                      stage(withoutRow(rows, spec, row.id));
                    }}
                  >
                    Remove
                  </button>
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {spec.fields.map((field) => (
                    <FieldControl
                      key={field.name}
                      field={field}
                      entry={row.entry}
                      stored={saved.find((s) => s.id === row.id)?.entry}
                      rowId={title}
                      editable={entry.editable}
                      onChange={set}
                    />
                  ))}
                </div>
                <OtherFieldsBox
                  entry={row.entry}
                  spec={spec}
                  title={title}
                  editable={entry.editable}
                  onChange={set}
                />
              </section>
            );
          })}
          <div className="flex items-center gap-2">
            {spec.shape === "map" && (
              <input
                aria-label={`Key of the new ${spec.noun}`}
                className={`${input} max-w-[14rem] font-mono`}
                placeholder={`new ${spec.noun} key`}
                disabled={!entry.editable}
                value={newKey}
                onChange={(e) => setNewKey(e.target.value)}
              />
            )}
            <button
              type="button"
              className={button}
              disabled={!entry.editable}
              onClick={() => {
                const made = withNewRow(rows, spec, newKey);
                if ("error" in made) {
                  setAddError(made.error);
                  return;
                }
                setAddError(null);
                setNewKey("");
                stage(made.rows);
              }}
            >
              Add {spec.noun}
            </button>
            {addError && (
              <span role="alert" className="text-[11px] text-status-red">
                {addError}
              </span>
            )}
          </div>
        </>
      )}
    </div>
  );
}
