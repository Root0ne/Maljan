"use client";

import { useEffect, useRef, useState } from "react";
import type { CatalogEntry, SettingValue } from "@/types/settings";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent disabled:opacity-50 disabled:cursor-not-allowed";

export interface WidgetProps {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown; // undefined when nothing is staged for this key
  onChange: (value: unknown) => void;
  /** Removes this key from `pending` entirely (distinct from `onChange`,
   * which always stages a value, even `null`/`undefined`). Used by
   * `NumberWidget` when a required field is emptied: there is nothing valid
   * to stage, so the edit is un-staged instead. */
  onUnstage?: () => void;
  /** Filled in by the LLM probe result so a model field renders a datalist. */
  models?: string[];
}

/** The value actually shown: the staged edit, else the live value, else the default. */
function shown(p: WidgetProps): unknown {
  return p.staged !== undefined ? p.staged : p.current?.value ?? p.entry.default;
}

export function BoolWidget(p: WidgetProps) {
  const v = Boolean(shown(p));
  return (
    <button
      type="button"
      role="switch"
      aria-checked={v}
      aria-label={p.entry.title}
      disabled={!p.entry.editable}
      onClick={() => p.onChange(!v)}
      className={`relative inline-flex h-5 w-9 shrink-0 rounded-full transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
        v ? "bg-accent" : "bg-border"
      } disabled:opacity-50 disabled:cursor-not-allowed`}
    >
      <span
        className={`inline-block h-4 w-4 mt-0.5 rounded-full bg-white transition-transform ${
          v ? "translate-x-4" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

function formatShown(p: WidgetProps): string {
  const v = shown(p);
  return v === null || v === undefined ? "" : String(v);
}

/**
 * A controlled number input whose *source of truth while typing* is a local
 * text buffer, not `shown(p)` — a plain `value={shown(p)}` input (as the
 * other widgets use) recomputes from props on every render, so clearing a
 * non-nullable field could never actually show empty: onChange would have
 * nothing valid to stage, the parent's state would not change, and the very
 * next render would snap the box back to the last staged/live number.
 *
 * The buffer is only re-synced from props when the *external* value moves
 * out from under the user — staged edits being cleared (discard, reset,
 * reset-group, or a successful apply all clear `pending`) or the live value
 * itself changing (a reset's reload landing new data) — never on every
 * keystroke, so mid-edit text (an empty box, a trailing decimal point) isn't
 * fought by a resync triggered by the very `onChange` that produced it.
 */
export function NumberWidget(p: WidgetProps) {
  const [requiredHint, setRequiredHint] = useState(false);
  const [text, setText] = useState(() => formatShown(p));
  const prevStagedRef = useRef(p.staged);
  const prevCurrentValueRef = useRef(p.current?.value);
  // Set right before this widget un-stages itself (required field cleared):
  // the resulting `staged: value -> undefined` transition is ours, not an
  // external discard/reset, and must not resync the (deliberately empty) box.
  const selfClearRef = useRef(false);
  const hintId = `number-required-${p.entry.key}`;

  useEffect(() => {
    const stagedJustCleared = prevStagedRef.current !== undefined && p.staged === undefined;
    const currentValueChanged = p.current?.value !== prevCurrentValueRef.current;
    const selfClear = selfClearRef.current && !currentValueChanged;
    selfClearRef.current = false;
    if (p.staged === undefined && (stagedJustCleared || currentValueChanged) && !selfClear) {
      setText(formatShown(p));
      setRequiredHint(false);
    }
    prevStagedRef.current = p.staged;
    prevCurrentValueRef.current = p.current?.value;
    // `p` itself is intentionally not a dependency: only these two fields
    // decide whether an external (not-from-this-widget) change happened.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [p.staged, p.current?.value]);

  return (
    <div>
      <input
        type="number"
        aria-label={p.entry.title}
        aria-describedby={requiredHint ? hintId : undefined}
        aria-invalid={requiredHint || undefined}
        className={input}
        disabled={!p.entry.editable}
        step={p.entry.type === "float" ? "any" : 1}
        min={p.entry.minimum ?? undefined}
        max={p.entry.maximum ?? undefined}
        value={text}
        onChange={(e) => {
          const raw = e.target.value;
          setText(raw);
          if (raw === "") {
            // Mirrors TextWidget: clearing a nullable field stages `null`.
            // Clearing a required one has nothing valid to stage, so it is
            // un-staged instead (falling back to the live/default value)
            // and an inline hint explains why the box is empty.
            if (p.entry.nullable) {
              setRequiredHint(false);
              p.onChange(null);
            } else {
              setRequiredHint(true);
              selfClearRef.current = true;
              p.onUnstage?.();
            }
            return;
          }
          const parsed = p.entry.type === "float" ? parseFloat(raw) : parseInt(raw, 10);
          if (Number.isNaN(parsed)) return; // mid-edit text (e.g. "-", "1."): wait for more input
          // An int field shows exactly what will be staged: "1.5" -> "1".
          if (p.entry.type !== "float" && raw !== String(parsed)) setText(String(parsed));
          setRequiredHint(false);
          p.onChange(parsed);
        }}
      />
      {requiredHint && (
        <div id={hintId} className="text-[11px] text-status-red mt-1" role="alert">
          Required — enter a value, or use &ldquo;Discard change&rdquo; / &ldquo;Reset to env&rdquo;.
        </div>
      )}
    </div>
  );
}

export function TextWidget(p: WidgetProps) {
  const v = shown(p);
  const list =
    p.models && p.models.length > 0 && /model$/.test(p.entry.path)
      ? `models-${p.entry.key}`
      : undefined;
  return (
    <>
      <input
        type="text"
        aria-label={p.entry.title}
        className={input}
        disabled={!p.entry.editable}
        list={list}
        value={v === null || v === undefined ? "" : String(v)}
        onChange={(e) =>
          p.onChange(e.target.value === "" && p.entry.nullable ? null : e.target.value)
        }
      />
      {list && (
        <datalist id={list}>
          {p.models!.map((m) => (
            <option key={m} value={m} />
          ))}
        </datalist>
      )}
    </>
  );
}

export function EnumWidget(p: WidgetProps) {
  const v = shown(p);
  return (
    <select
      aria-label={p.entry.title}
      className={input}
      disabled={!p.entry.editable}
      value={String(v ?? "")}
      onChange={(e) => p.onChange(e.target.value)}
    >
      {(p.entry.choices ?? []).map((c) => (
        <option key={c} value={c}>
          {c}
        </option>
      ))}
    </select>
  );
}

export function ListWidget(p: WidgetProps) {
  const v = (shown(p) as string[] | null) ?? [];
  return (
    <textarea
      aria-label={p.entry.title}
      className={`${input} font-mono`}
      rows={Math.min(6, Math.max(2, v.length))}
      disabled={!p.entry.editable}
      placeholder="one entry per line"
      value={v.join("\n")}
      onChange={(e) =>
        p.onChange(e.target.value.split("\n").map((s) => s.trim()).filter(Boolean))
      }
    />
  );
}

export function JsonWidget(p: WidgetProps) {
  const initial = JSON.stringify(shown(p) ?? (p.entry.type === "dict" ? {} : null), null, 2);
  const [text, setText] = useState(initial);
  const [bad, setBad] = useState<string | null>(null);
  return (
    <div>
      <textarea
        aria-label={p.entry.title}
        aria-invalid={bad ? true : undefined}
        className={`${input} font-mono`}
        rows={Math.min(14, Math.max(3, text.split("\n").length))}
        disabled={!p.entry.editable}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          try {
            p.onChange(JSON.parse(e.target.value));
            setBad(null);
          } catch (err) {
            setBad((err as Error).message);
          }
        }}
      />
      {bad && (
        <div className="text-[11px] text-status-red mt-1" role="alert">
          Invalid JSON: {bad}
        </div>
      )}
    </div>
  );
}

export function SecretWidget(p: WidgetProps) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const isSet = p.staged !== undefined ? p.staged !== null : Boolean(p.current?.is_set);
  const status =
    p.staged !== undefined
      ? p.staged === null
        ? "will be cleared"
        : "new value staged"
      : p.current?.is_set
        ? `set · …${p.current.hint ?? ""} · ${p.current.source}`
        : "not set";
  if (!p.entry.editable) {
    return (
      <div className="text-sm text-text-muted">
        {status}
        {p.entry.reason ? ` — ${p.entry.reason}` : ""}
      </div>
    );
  }
  return (
    <div className="flex items-center gap-2 flex-wrap">
      {editing ? (
        <>
          <label className="sr-only" htmlFor={`secret-${p.entry.key}`}>
            New value for {p.entry.title}
          </label>
          <input
            id={`secret-${p.entry.key}`}
            type="password"
            autoComplete="new-password"
            className={input}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="paste the new value"
          />
          <button
            type="button"
            className="text-xs text-accent-strong"
            onClick={() => {
              p.onChange(draft);
              setEditing(false);
              setDraft("");
            }}
          >
            Stage
          </button>
          <button
            type="button"
            className="text-xs text-text-secondary"
            onClick={() => {
              setEditing(false);
              setDraft("");
            }}
          >
            Cancel
          </button>
        </>
      ) : (
        <>
          <span className="text-sm text-text-muted">{status}</span>
          <button
            type="button"
            className="text-xs text-accent-strong"
            onClick={() => setEditing(true)}
          >
            Set new value
          </button>
          {isSet && (
            <button
              type="button"
              className="text-xs text-status-red"
              onClick={() => p.onChange(null)}
            >
              Clear
            </button>
          )}
        </>
      )}
    </div>
  );
}

export function Widget(p: WidgetProps) {
  switch (p.entry.type) {
    case "bool":
      return <BoolWidget {...p} />;
    case "int":
    case "float":
      return <NumberWidget {...p} />;
    case "enum":
      return <EnumWidget {...p} />;
    case "list":
      return <ListWidget {...p} />;
    case "dict":
    case "json":
      return <JsonWidget {...p} />;
    case "secret":
      return <SecretWidget {...p} />;
    default:
      return <TextWidget {...p} />;
  }
}
