"use client";

import type { McpServerEntry } from "@/types/settings";
import {
  acceptField,
  acceptServerField,
  acceptTool,
  isAccepted,
  showValue,
  type Proposals,
  type ProposedField,
} from "./declarationProposals";

function FieldRow({
  label,
  field,
  accepted,
  onAccept,
}: {
  label: string;
  field: ProposedField;
  accepted: boolean;
  onAccept: () => void;
}) {
  return (
    <li className="flex items-start justify-between gap-2" data-proposal-field={label}>
      <div className="min-w-0">
        <span className="font-mono text-text-primary">{label}</span>
        {": "}
        <span className="font-mono break-all">{showValue(field.value)}</span>
        <div className="text-[10px] text-text-muted">
          <span className="text-text-secondary">{field.confidence} confidence</span>
          {" · from "}
          {field.evidence.join("; ")}
        </div>
      </div>
      <button
        type="button"
        className="text-[11px] text-accent-strong disabled:opacity-50 shrink-0"
        disabled={accepted}
        aria-label={`accept ${label}`}
        onClick={onAccept}
      >
        {accepted ? "accepted" : "accept"}
      </button>
    </li>
  );
}

/**
 * The declarations a probe proposes for the tools nobody declared, each field
 * with where it was read and how sure the reading is.
 *
 * Nothing is applied until an admin accepts it, and accepting only stages the
 * field into this server's declaration, as typing it would; Apply saves it.
 * Every value shown is the server's data, rendered as text.
 */
export default function DeclarationProposals({
  serverKey,
  server,
  proposals,
  put,
}: {
  serverKey: string;
  server: McpServerEntry;
  proposals: Proposals;
  put: (next: Partial<McpServerEntry>) => void;
}) {
  const tools = Object.entries(proposals.tools);
  const serverFields = Object.entries(proposals.server);
  if (tools.length === 0 && serverFields.length === 0) return null;
  return (
    <details className="mt-2 border border-border rounded p-2" data-proposals={serverKey} open>
      <summary className="text-xs text-text-muted cursor-pointer">
        Proposed declarations ({tools.length} undeclared tools)
      </summary>
      <p className="text-[11px] text-text-secondary mt-1">
        Read from what the server says about its tools. Nothing is used until you accept it;
        accepting stages it in this server&apos;s declaration, and Apply saves it.
      </p>
      <div className="space-y-2 mt-2 text-xs">
        {tools.map(([tool, proposal]) => (
          <fieldset key={tool} className="border border-border rounded p-2" data-proposal-tool={tool}>
            <legend className="px-1 flex items-center gap-2">
              <span className="font-mono text-text-primary">{tool}</span>
              {proposals.probed?.[tool] && (
                <span className="text-[10px] text-text-muted">probe call: {proposals.probed[tool]}</span>
              )}
              <button
                type="button"
                className="text-[11px] text-accent-strong"
                aria-label={`accept every field of ${tool}`}
                onClick={() => put(acceptTool(server, tool, proposal))}
              >
                accept tool
              </button>
            </legend>
            <ul className="space-y-1">
              {Object.entries(proposal.fields).map(([field, held]) => (
                <FieldRow
                  key={field}
                  label={field}
                  field={held}
                  accepted={isAccepted(server, tool, field, proposal)}
                  onAccept={() => put(acceptField(server, tool, proposal, field))}
                />
              ))}
            </ul>
            {proposal.notes?.map((note) => (
              <p key={note} className="text-[10px] text-text-muted">{note}</p>
            ))}
          </fieldset>
        ))}
        {serverFields.length > 0 && (
          <fieldset className="border border-border rounded p-2" data-proposal-tool="(server)">
            <legend className="px-1 text-text-muted">server</legend>
            <ul className="space-y-1">
              {serverFields.map(([field, held]) => (
                <FieldRow
                  key={field}
                  label={field}
                  field={held}
                  accepted={false}
                  onAccept={() => put(acceptServerField(server, field, held))}
                />
              ))}
            </ul>
          </fieldset>
        )}
      </div>
    </details>
  );
}
