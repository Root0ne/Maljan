"use client";

import { FileSearch } from "lucide-react";
import { useReport } from "./AnalysisContext";
import { citationParts } from "./citations";
import { splitCitations } from "./overview";

/**
 * Report prose with its inline evidence citations turned into links.
 *
 * Each bracketed group of ids (`splitCitations`) is drawn as one small
 * superscript mark that opens the evidence drawer on those records; the ids
 * themselves are never printed in the prose. A bare id (`ev_0006`, outside
 * any bracket) is marked the same way.
 */
export default function CitedProse({ text }: { text: string }) {
  return (
    <>
      {splitCitations(text).map((part, i) =>
        part.kind === "text" ? <BareIds key={i} text={part.text} /> : <CiteMark key={i} ids={part.ids} />,
      )}
    </>
  );
}

function BareIds({ text }: { text: string }) {
  return (
    <span>
      {citationParts(text).map((part, i) =>
        part.kind === "id" ? <CiteMark key={i} ids={[part.id]} named /> : part.text,
      )}
    </span>
  );
}

/**
 * One citation as a reader sees it outside the Evidence tab: a small
 * superscript mark that opens the evidence drawer on the records it names.
 * `title` heads the drawer.
 */
export function CiteMark({
  ids,
  title = "Evidence for this statement",
  named = false,
}: {
  ids: readonly string[];
  title?: string;
  /** The id was written in the text: say it in the mark's name too, so the
   *  reader loses nothing the plain text gave. */
  named?: boolean;
}) {
  const { showEvidence } = useReport();
  if (ids.length === 0) return null;
  return (
    <sup className="ml-0.5">
      <button
        type="button"
        data-citation=""
        onClick={(e) =>
          showEvidence?.({ title, details: [], techniques: [], evidenceIds: [...ids] }, e.currentTarget)
        }
        title={ids.join(", ")}
        aria-label={`${title}, ${ids.length} record${ids.length === 1 ? "" : "s"}${named ? ` (${ids.join(", ")})` : ""}`}
        className="inline-flex h-4 min-w-4 items-center justify-center rounded px-0.5 leading-none text-accent-strong hover:bg-bg-active"
      >
        <FileSearch aria-hidden="true" className="h-3 w-3" />
      </button>
    </sup>
  );
}
