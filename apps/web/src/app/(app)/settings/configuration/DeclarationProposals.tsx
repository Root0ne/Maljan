"use client";

import { shippedServerToolFacts } from "@/lib/providerFacts";
import type { McpServerEntry } from "@/types/settings";
import { usableFields } from "./declarationFields";
import { useOptionalSettingsContext } from "./SettingsContext";
import {
  OPEN_UP_TO,
  acceptField,
  acceptServerField,
  stillIncomplete,
  acceptTool,
  alsoStaged,
  hasProposal,
  isAccepted,
  showValue,
  type PlannedCall,
  type Proposals,
  type ProposedField,
} from "./declarationProposals";

function FieldRow({
  label,
  field,
  also,
  accepted,
  missing = [],
  onAccept,
}: {
  label: string;
  field: ProposedField;
  also: string[];
  accepted: boolean;
  /** Fields to declare before this can be accepted. */
  missing?: string[];
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
      <div className="shrink-0 text-right">
        <button
          type="button"
          className="text-[11px] text-accent-strong disabled:opacity-50"
          disabled={accepted || missing.length > 0}
          aria-label={`accept ${label}`}
          onClick={onAccept}
        >
          {accepted ? "accepted" : "accept"}
        </button>
        {!accepted && missing.length > 0 && (
          <div className="text-[10px] text-text-muted" data-proposal-incomplete>
            declare first: {missing.join(", ")}
          </div>
        )}
        {!accepted && also.length > 0 && (
          <div className="text-[10px] text-text-muted">also stages {also.join(", ")}</div>
        )}
      </div>
    </li>
  );
}

/** The harmless calls the probe would make, listed before any is made. */
function PlannedCalls({
  planned,
  busy,
  onConfirm,
}: {
  planned: PlannedCall[];
  busy: boolean;
  onConfirm: (tools: string[]) => void;
}) {
  return (
    <fieldset className="border border-border rounded p-2" data-planned-calls>
      <legend className="px-1 text-text-muted">One harmless call per tool</legend>
      <p className="text-[11px] text-text-secondary">
        Only tools their server marks read-only are listed. These tools are called once each
        with the values shown, never a sample, on this server exactly as it is configured (its
        URL, arguments and files); only what each line says is withheld is withheld, and a call
        that fails without it says so. A tool that reaches its own service is asked about these
        values. Nothing is called until you confirm.
      </p>
      <ul className="space-y-1 mt-1">
        {planned.map((call) => (
          <li key={call.tool} className="font-mono break-all" data-planned-call={call.tool}>
            {call.tool} {JSON.stringify(call.arguments)}
            <span className="text-[10px] text-text-muted font-sans">
              {call.remote ? " · may reach its own service" : " · stays on this server"}
              {call.credential
                ? " · with this server's credential (its declaration needs one)"
                : call.withheld.length
                  ? ` · withheld: ${call.withheld.join(", ")}`
                  : " · nothing withheld"}
            </span>
          </li>
        ))}
      </ul>
      <button
        type="button"
        className="mt-1 text-[11px] text-accent-strong disabled:opacity-50"
        disabled={busy}
        onClick={() => onConfirm(planned.map((call) => call.tool))}
      >
        Call these {planned.length} tools once each
      </button>
    </fieldset>
  );
}

/**
 * The declarations a probe proposes for the tools nobody declared, each field
 * with where it was read and how sure the reading is.
 *
 * Nothing is applied until an admin accepts it, and accepting only stages the
 * field into this server's declaration, as typing it would; Apply saves it.
 * A tool nothing proposes anything for is listed on one line. Every value
 * shown is the server's data, rendered as text.
 */
export default function DeclarationProposals({
  serverKey,
  server,
  proposals,
  put,
  onConfirmCalls,
  busy = false,
}: {
  serverKey: string;
  server: McpServerEntry;
  proposals: Proposals;
  put: (next: Partial<McpServerEntry>) => void;
  onConfirmCalls?: (tools: string[]) => void;
  busy?: boolean;
}) {
  const schema = useOptionalSettingsContext()?.schema;
  const declared = {
    shipped: shippedServerToolFacts(schema, serverKey),
    fields: usableFields(schema?.tool_declaration_fields),
  };
  const tools = Object.entries(proposals.tools);
  const proposing = tools.filter(([, proposal]) => hasProposal(proposal));
  const quiet = tools.filter(([, proposal]) => !hasProposal(proposal)).map(([tool]) => tool);
  const serverFields = Object.entries(proposals.server);
  const failed = Object.entries(proposals.failed ?? {});
  const planned = proposals.planned ?? [];
  const notes = proposals.notes ?? [];
  if (
    tools.length === 0 &&
    serverFields.length === 0 &&
    failed.length === 0 &&
    notes.length === 0
  ) {
    return null;
  }
  return (
    <details
      className="mt-2 border border-border rounded p-2"
      data-proposals={serverKey}
      open={proposing.length <= OPEN_UP_TO}
    >
      <summary className="text-xs text-text-muted cursor-pointer">
        Proposed declarations ({proposing.length} of {tools.length} undeclared tools)
      </summary>
      <p className="text-[11px] text-text-secondary mt-1">
        Read from what the server says about its tools. Nothing is used until you accept it;
        accepting stages it in this server&apos;s declaration, and Apply saves it. A tool keeps
        what an undeclared tool gets until you accept a kind for it. Only the tools you
        accept are stored; every other tool keeps following what the server ships.
      </p>
      {notes.map((note) => (
        <p key={note} className="text-[11px] text-text-secondary mt-1" data-proposal-note>
          {note}
        </p>
      ))}
      <div className="space-y-2 mt-2 text-xs">
        {proposing.map(([tool, proposal]) => (
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
                onClick={() => put(acceptTool(server, tool, proposal, declared))}
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
                  also={alsoStaged(server, tool, proposal, field, declared)}
                  accepted={isAccepted(server, tool, field, proposal, declared)}
                  onAccept={() => put(acceptField(server, tool, proposal, field, declared))}
                />
              ))}
            </ul>
            {proposal.notes?.map((note) => (
              <p key={note} className="text-[10px] text-text-muted">{note}</p>
            ))}
          </fieldset>
        ))}
        {quiet.length > 0 && (
          <p className="text-[11px] text-text-muted" data-proposal-quiet>
            Nothing proposed for: <span className="font-mono">{quiet.join(", ")}</span>
          </p>
        )}
        {failed.map(([tool, reason]) => (
          <p key={tool} className="text-[11px] text-text-muted" data-proposal-failed={tool}>
            <span className="font-mono">{tool}</span>: {reason}
          </p>
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
                  also={[]}
                  accepted={false}
                  missing={stillIncomplete(server, field, held)}
                  onAccept={() => put(acceptServerField(server, field, held))}
                />
              ))}
            </ul>
          </fieldset>
        )}
        {planned.length > 0 && onConfirmCalls && !proposals.probed && (
          <PlannedCalls planned={planned} busy={busy} onConfirm={onConfirmCalls} />
        )}
      </div>
    </details>
  );
}
