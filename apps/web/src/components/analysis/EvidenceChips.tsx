"use client";

import Link from "next/link";
import { useParams } from "next/navigation";

import { useReport } from "./AnalysisContext";
import { CiteMark } from "./CitedProse";
import { citationParts, isEvidenceId } from "./citations";

/**
 * The evidence records a section or a finding was built from, as links.
 *
 * A citation is only worth printing if a reader can follow it, so an id is
 * never rendered as bare text here. Inside an analysis page the ids are not
 * printed at all: the bare ids become one superscript mark and each id inside
 * a citation sentence its own, every mark opening the evidence drawer, which
 * links on to the records. Outside one (the run diff) each id is a chip that
 * links straight to its record. The job id comes from the route rather than a
 * prop because every other caller is already inside `analysis/[id]`.
 */
export default function EvidenceChips({
  ids,
  source,
  jobId: jobIdProp,
  className = "",
}: {
  ids: string[] | null | undefined;
  /** The run the ids belong to, for a caller outside `analysis/[id]` — the
   *  run diff cites two runs on one page. The route's id otherwise. */
  jobId?: string;
  /** Where the section came from when it cites no entry — `tool`, `routing`,
   *  `agent` or `agent:<name>`. Printed as a plain chip: it is a provenance
   *  claim, not a citation, and nothing resolves it. */
  source?: string;
  className?: string;
}) {
  const params = useParams();
  const { showEvidence } = useReport();
  const jobId = jobIdProp ?? (typeof params?.id === "string" ? params.id : "");
  const entries = (ids ?? []).filter(
    (id) => typeof id === "string" && id.trim().length > 0,
  );

  if (entries.length === 0 && !source) return null;

  const sourceChip = entries.length === 0 && source && (
    <span
      className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-bg-active text-text-muted"
      title="No evidence record; this is the finding the section came from"
    >
      {source}
    </span>
  );

  if (showEvidence) {
    const bare = entries.filter(isEvidenceId).map((id) => id.trim());
    const prose = entries.filter((id) => !isEvidenceId(id));
    return (
      <span className={`inline ${className}`}>
        <CiteMark ids={bare} />
        {prose.map((text, i) => (
          <span key={i} className="inline text-[11px] text-text-muted">
            {" "}
            {citationParts(text).map((part, j) =>
              part.kind === "id" ? <CiteMark key={j} ids={[part.id]} /> : <span key={j}>{part.text}</span>,
            )}
          </span>
        ))}
        {sourceChip}
      </span>
    );
  }

  return (
    <span className={`inline-flex flex-wrap items-center gap-1 ${className}`}>
      {entries.map((entry, i) =>
        /* An entry that is an id is a chip. One that is a sentence citing
           several — an analyst's `evidence_ref` — is a chip per id it names,
           with its own words between them as words: the whole sentence as one
           `?evidence=` link opened nothing. */
        isEvidenceId(entry) ? (
          <EvidenceChip key={i} id={entry.trim()} jobId={jobId} />
        ) : (
          <CitationProse key={i} text={entry} jobId={jobId} />
        ),
      )}
      {sourceChip}
    </span>
  );
}

/** One evidence id, as the link that opens its row in the evidence panel. */
function EvidenceChip({ id, jobId }: { id: string; jobId: string }) {
  return (
    <Link
      href={`/analysis/${jobId}/evidence?evidence=${encodeURIComponent(id)}`}
      className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-accent/15 text-accent-strong hover:bg-accent/25"
      title="Open this record in the evidence"
    >
      {id}
    </Link>
  );
}

/* Inline, not flex: a flex item drops its edge whitespace, so "ev_0019." and
 * "ev_0024 (row" would lose or gain the spaces they were written with. */
function CitationProse({ text, jobId }: { text: string; jobId: string }) {
  return (
    <span className="inline text-[11px] text-text-muted">
      {citationParts(text).map((part, i) =>
        part.kind === "id" ? (
          <EvidenceChip key={i} id={part.id} jobId={jobId} />
        ) : (
          <span key={i}>{part.text}</span>
        ),
      )}
    </span>
  );
}

/**
 * A run of prose with the evidence ids in it as links: a section's note ("18
 * more rows not shown here; the evidence endpoint carries every one under
 * ev_0005") names the record to open, and the name is only worth printing if
 * it opens. Inside an analysis page each id is a superscript mark that opens
 * the evidence drawer. Everything that is not an id is printed exactly as
 * written.
 */
export function CitedText({ text, jobId: jobIdProp }: { text: string; jobId?: string }) {
  const params = useParams();
  const { showEvidence } = useReport();
  const jobId = jobIdProp ?? (typeof params?.id === "string" ? params.id : "");
  const marks = Boolean(showEvidence);
  return (
    <>
      {citationParts(text).map((part, i) =>
        part.kind === "id" && marks ? (
          <CiteMark key={i} ids={[part.id]} />
        ) : part.kind === "id" ? (
          <Link
            key={i}
            href={`/analysis/${jobId}/evidence?evidence=${encodeURIComponent(part.id)}`}
            className="font-mono text-accent-strong hover:underline"
            title="Open this record in the evidence"
          >
            {part.id}
          </Link>
        ) : (
          part.text
        ),
      )}
    </>
  );
}
