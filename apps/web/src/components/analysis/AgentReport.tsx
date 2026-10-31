"use client";

import { Fragment } from "react";
import CitedProse, { CiteMark } from "./CitedProse";
import SafeMarkdown from "./SafeMarkdown";
import { citedRecords } from "./citations";
import { parseAgentReport, type ReportClaim } from "./debate";

/**
 * One analyst's report as a reader goes through it (`parseAgentReport`):
 * its claims as rows, each with the records it cites and the confidence the
 * analyst gave it; the lists its summary closes with (open questions,
 * disputes, findings) as lists; then the analyst's own prose as Markdown with
 * the report's one citation mark.
 *
 * A claim is the analyst's words about the sample and is kept as written,
 * paths and commands included; only its evidence ids become links. The prose
 * is drawn as Markdown with every backslash kept (`keepBackslashes`). `name`
 * names the report's scroll regions apart from every other block's.
 */
export default function AgentReport({
  report,
  name,
  truncated = false,
}: {
  report: string;
  name: string;
  truncated?: boolean;
}) {
  const parsed = parseAgentReport(report);
  return (
    <div className="space-y-4">
      {parsed.claims.length > 0 && (
        <ol aria-label={`Claims in ${name}`} className="max-w-4xl divide-y divide-border-light">
          {parsed.claims.map((claim, i) => (
            <ClaimRow key={`${claim.number}-${i}`} claim={claim} />
          ))}
        </ol>
      )}
      {parsed.lists.map((list, i) => (
        <section key={`${list.title}-${i}`} aria-label={`${list.title} in ${name}`} className="max-w-[75ch] space-y-1">
          <h4 className="text-xs font-medium text-text-secondary">{list.title}</h4>
          {list.items.length === 0 ? (
            <p className="text-sm text-text-muted">None listed.</p>
          ) : (
            <ul className="list-disc space-y-1.5 pl-5 text-sm leading-6 text-text-primary">
              {list.items.map((item, j) => (
                <ListItem key={j} item={item} />
              ))}
            </ul>
          )}
        </section>
      ))}
      {parsed.signals.map((signal, i) => (
        <p key={`signal-${i}`} className="text-xs text-text-secondary">
          {signalWords(signal)}
        </p>
      ))}
      {parsed.prose && (
        <SafeMarkdown
          markdown={parsed.prose}
          keepBackslashes
          cite
          regionName={name}
          className="max-w-[75ch] space-y-3 text-sm leading-6 text-text-primary"
        />
      )}
      {parsed.claims.length === 0 && !parsed.prose && (
        <p className="text-sm text-text-muted">The report is empty.</p>
      )}
      {truncated && <p className="text-xs text-text-muted">The producer cut this report at its size limit.</p>}
    </div>
  );
}

/** A summary note in words: `CONVERGENCE SIGNAL: no remaining disputes` reads "No remaining disputes." */
function signalWords(signal: string): string {
  const said = signal.replace(/^[A-Z ]*SIGNAL:\s*/, "").trim() || signal;
  return `${said.charAt(0).toUpperCase()}${said.slice(1)}.`;
}

/**
 * One item of a list, as written. An open question's fields (`<question> |
 * Why open: tool_failed | Detail: ...`) are set under it, one a line.
 */
function ListItem({ item }: { item: string }) {
  const [first, ...fields] = item.split(" | ");
  return (
    <li className="whitespace-pre-wrap break-words">
      <CitedProse text={first} />
      {fields.map((field, i) => (
        <span key={i} className="block text-xs text-text-secondary">
          <CitedProse text={field} />
        </span>
      ))}
    </li>
  );
}

function ClaimRow({ claim }: { claim: ReportClaim }) {
  return (
    <li className="grid grid-cols-[2.5rem_minmax(0,1fr)_auto] gap-x-3 py-2.5 text-sm">
      <span className="pt-px text-xs text-text-muted tabular-nums">{claim.number}</span>
      <div className="min-w-0 space-y-1">
        {claim.topic && <p className="text-xs text-text-secondary">{claim.topic}</p>}
        {/* The analyst's words as written: a path keeps its backslashes. */}
        <p className="whitespace-pre-wrap break-words leading-6 text-text-primary">
          <CitedProse text={claim.text} />
        </p>
        {claim.evidence && <EvidenceRefs text={claim.evidence} />}
      </div>
      <span className="pt-px text-xs text-text-secondary tabular-nums" title="The confidence the analyst gave this claim">
        {claim.confidence === null ? "" : `${Math.round(claim.confidence * 100)}%`}
      </span>
    </li>
  );
}

/**
 * The records a claim cites, each as the page's one citation mark (which
 * opens it in the evidence drawer, its id in the mark's name) followed by the
 * words written after it (`citedRecords`).
 */
export function EvidenceRefs({ text }: { text: string }) {
  const { lead, records } = citedRecords(text);
  if (records.length === 0) {
    return <p className="whitespace-pre-wrap break-words text-xs text-text-secondary">{text}</p>;
  }
  return (
    <p className="break-words text-xs leading-5 text-text-secondary">
      <span className="text-text-muted">{lead || "Evidence"}</span>
      {records.map((record, i) => (
        <Fragment key={`${record.id}-${i}`}>
          {i > 0 && ";"}
          <CiteMark ids={[record.id]} named />
          {record.label && <span className="whitespace-pre-wrap"> {record.label}</span>}
        </Fragment>
      ))}
    </p>
  );
}
