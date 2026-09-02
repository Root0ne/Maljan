"use client";

import { useState } from "react";
import type { CatalogEntry, SettingValue } from "@/types/settings";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent disabled:opacity-50 disabled:cursor-not-allowed";

export interface WidgetProps {
  entry: CatalogEntry;
  current: SettingValue | undefined;
  staged: unknown; // undefined when nothing is staged for this key
  onChange: (value: unknown) => void;
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

export function NumberWidget(p: WidgetProps) {
  const v = shown(p);
  const [requiredHint, setRequiredHint] = useState(false);
  const hintId = `number-required-${p.entry.key}`;
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
        value={v === null || v === undefined ? "" : String(v)}
        onChange={(e) => {
          if (e.target.value === "") {
            // Mirrors TextWidget: clearing a nullable field stages `null`;
            // clearing a required one stages nothing and shows an inline
            // hint instead of silently proposing a null value the backend
            // would reject.
            if (p.entry.nullable) {
              setRequiredHint(false);
              p.onChange(null);
            } else {
              setRequiredHint(true);
            }
            return;
          }
          setRequiredHint(false);
          p.onChange(
            p.entry.type === "float" ? parseFloat(e.target.value) : parseInt(e.target.value, 10)
          );
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
