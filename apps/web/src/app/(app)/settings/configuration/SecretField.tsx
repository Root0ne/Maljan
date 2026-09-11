"use client";

import { useState } from "react";

const input =
  "w-full bg-bg-deep border border-border rounded px-2 py-1.5 text-sm text-text-primary focus:outline-none focus:border-accent disabled:opacity-50 disabled:cursor-not-allowed";

export type SecretStatus = "set" | "not-set" | "staged" | "cleared";

/** The one status line every secret shows, in the wording the e2e spec pins:
 *  `set · …<hint> · <source>`, `not set`, `new value staged`, `will be cleared`. */
function secretStatusText(
  status: SecretStatus,
  hint?: string | null,
  source?: "default" | "ui"
): string {
  switch (status) {
    case "staged":
      return "new value staged";
    case "cleared":
      return "will be cleared";
    case "set":
      return `set · …${hint ?? ""} · ${source ?? "default"}`;
    default:
      return "not set";
  }
}

/**
 * The shared secret control: a status line plus the "Set new value" →
 * password input → "Stage"/"Cancel" flow and a "Clear". Used by the secret
 * row type here and by the server card's auth token, so both speak one set of
 * verbs. The value itself is never rendered back — only its status and hint.
 */
export default function SecretField({
  id,
  name,
  title,
  status,
  hint,
  source,
  editable,
  reason,
  onStage,
  onClear,
  onCancel,
  labels,
  statusText,
  statusAttrs,
}: {
  id: string;
  name: string;
  /** Names the field in the sr-only label over the password input. */
  title?: string;
  status: SecretStatus;
  hint?: string | null;
  source?: "default" | "ui";
  editable: boolean;
  reason?: string | null;
  onStage: (value: string) => void;
  onClear: () => void;
  onCancel: () => void;
  labels?: { replace?: string };
  /** Wording a caller's own contract pins, in place of the computed line: the
   *  tool-server token says where it comes from (`set from the UI`) rather
   *  than `set · …hint · source`, and that text is asserted by the servers
   *  spec. */
  statusText?: string;
  /** Attributes for the element the status line is rendered in, so a caller
   *  can keep a hook it already published — `data-token-state` on the server
   *  token. Only applied while the field is closed, which is the only time a
   *  status is shown at all. */
  statusAttrs?: Record<string, string>;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState("");
  const line = statusText ?? secretStatusText(status, hint, source);
  const replaceLabel = labels?.replace ?? "Set new value";

  if (!editable) {
    return (
      <div className="text-sm text-text-muted" {...statusAttrs}>
        {line}
        {reason ? ` — ${reason}` : ""}
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      {editing ? (
        <>
          <label className="sr-only" htmlFor={id}>
            New value{title ? ` for ${title}` : ""}
          </label>
          <input
            id={id}
            name={name}
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
              onStage(draft);
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
              onCancel();
            }}
          >
            Cancel
          </button>
        </>
      ) : (
        <>
          <span className="text-sm text-text-muted" {...statusAttrs}>
            {line}
          </span>
          <button
            type="button"
            className="text-xs text-accent-strong"
            onClick={() => setEditing(true)}
          >
            {replaceLabel}
          </button>
          {status !== "not-set" && (
            <button type="button" className="text-xs text-status-red" onClick={onClear}>
              Clear
            </button>
          )}
        </>
      )}
    </div>
  );
}
