"use client";

import { useState } from "react";

import {
  parseDeclaration,
  shownFields,
  showValue,
  type ReportFormatProposal as Proposal,
} from "./reportFormatProposal";

/** An unread upload's proposed format declaration: each field with its evidence, the
 *  whole as editable JSON, and an accept an admin sends. Everything is drawn as text. */
export default function ReportFormatProposal({
  proposal,
  busy,
  error,
  onAccept,
}: {
  proposal: Proposal;
  busy: boolean;
  error: string | null;
  onAccept: (declaration: Record<string, unknown>) => void;
}) {
  const [text, setText] = useState(() =>
    proposal.declaration ? JSON.stringify(proposal.declaration, null, 2) : ""
  );
  const [invalid, setInvalid] = useState<string | null>(null);

  function accept() {
    const read = parseDeclaration(text);
    if (!read.ok) {
      setInvalid(read.error);
      return;
    }
    setInvalid(null);
    onAccept(read.value);
  }

  return (
    <div className="mt-2 border border-border rounded p-2 space-y-2" data-format-proposal>
      <p className="text-text-secondary">
        Proposed format declaration, read from the report&apos;s shape. Nothing is applied
        until an admin accepts it; until then the report is read unread.
      </p>
      <ul className="space-y-1">
        {shownFields(proposal).map(([name, field]) => (
          <li key={name} data-format-proposal-field={name}>
            <span className="font-mono text-text-primary">{name}</span>
            {": "}
            <span className="font-mono break-all">{showValue(field.value)}</span>
            <div className="text-[10px] text-text-muted">
              <span className="text-text-secondary">{field.confidence} confidence</span>
              {" · from "}
              {field.evidence.join("; ")}
            </div>
          </li>
        ))}
      </ul>
      {proposal.failed && <p className="text-text-muted">{proposal.failed}</p>}
      {proposal.declaration && (
        <>
          <label htmlFor="format-declaration" className="block text-text-muted">
            Declaration (edit before accepting)
          </label>
          <textarea
            id="format-declaration"
            value={text}
            onChange={(e) => setText(e.target.value)}
            rows={10}
            spellCheck={false}
            className="w-full font-mono text-[11px] border border-border rounded p-1 bg-bg-surface text-text-primary"
          />
          {(invalid || error) && <p className="text-status-red">{invalid || error}</p>}
          <button
            type="button"
            disabled={busy}
            onClick={accept}
            className="px-2.5 py-1 text-xs border border-border text-text-secondary rounded hover:bg-bg-hover disabled:opacity-50"
          >
            Accept this declaration
          </button>
        </>
      )}
    </div>
  );
}
