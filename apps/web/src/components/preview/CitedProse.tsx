"use client";

import { FileSearch } from "lucide-react";
import { usePreview } from "./PreviewFrame";
import { splitCitations } from "./overview";

/**
 * Report prose with its inline evidence citations turned into links.
 *
 * Each bracketed group of ids (`splitCitations`) is drawn as one small
 * superscript mark that opens the evidence drawer on those records; the ids
 * themselves are never printed in the prose.
 */
export default function CitedProse({ text }: { text: string }) {
  const { showEvidence } = usePreview();
  return (
    <>
      {splitCitations(text).map((part, i) =>
        part.kind === "text" ? (
          <span key={i}>{part.text}</span>
        ) : (
          <sup key={i} className="ml-0.5">
            <button
              type="button"
              data-citation=""
              onClick={(e) =>
                showEvidence(
                  { title: "Evidence for this statement", details: [], techniques: [], evidenceIds: part.ids },
                  e.currentTarget,
                )
              }
              aria-label={`Evidence for this statement, ${part.ids.length} record${part.ids.length === 1 ? "" : "s"}`}
              className="inline-flex h-4 min-w-4 items-center justify-center rounded px-0.5 leading-none text-accent-strong hover:bg-bg-active"
            >
              <FileSearch aria-hidden="true" className="h-3 w-3" />
            </button>
          </sup>
        ),
      )}
    </>
  );
}
