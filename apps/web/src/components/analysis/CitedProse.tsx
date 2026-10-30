"use client";

import { FileSearch } from "lucide-react";
import { useReport } from "./AnalysisContext";
import { splitCitations } from "./overview";

/**
 * Report prose with its inline evidence citations turned into links.
 *
 * Each bracketed group of ids (`splitCitations`) is drawn as one small
 * superscript mark that opens the evidence drawer on those records; the ids
 * themselves are never printed in the prose.
 */
export default function CitedProse({ text }: { text: string }) {
  return (
    <>
      {splitCitations(text).map((part, i) =>
        part.kind === "text" ? <span key={i}>{part.text}</span> : <CiteMark key={i} ids={part.ids} />,
      )}
    </>
  );
}

/**
 * One citation as a reader sees it outside the Evidence tab: a small
 * superscript mark that opens the evidence drawer on the records it names.
 * `title` heads the drawer.
 */
export function CiteMark({ ids, title = "Evidence for this statement" }: { ids: readonly string[]; title?: string }) {
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
        aria-label={`${title}, ${ids.length} record${ids.length === 1 ? "" : "s"}`}
        className="inline-flex h-4 min-w-4 items-center justify-center rounded px-0.5 leading-none text-accent-strong hover:bg-bg-active"
      >
        <FileSearch aria-hidden="true" className="h-3 w-3" />
      </button>
    </sup>
  );
}
