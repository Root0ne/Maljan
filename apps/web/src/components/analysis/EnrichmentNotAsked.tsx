"use client";

import Section from "@/components/ui/Section";
import Th from "@/components/ui/Th";
import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import type { EnrichmentNotAsked as NotAskedRow } from "@/types/malware-report";

/** What a question the enrichment would have asked is about, in words. */
const QUESTION_WORDS: Record<string, string> = {
  reputation: "reputation",
  asn: "ASN",
  geo: "geography",
};

/**
 * The network values the post-verdict enrichment left unasked, beside the
 * button that asks it: it asks at most the operator's per-kind lookup cap
 * (`enrichment_max_lookups`), and each value past the cap is listed with the
 * questions it was not asked. A host on this tab with no reputation is then
 * read as "not asked", never as "clean". Drawn only when the report lists
 * any; a report that lists none had every value asked, or ran no enrichment.
 */
export default function EnrichmentNotAsked({ rows }: { rows: readonly NotAskedRow[] | null | undefined }) {
  const list = rows ?? [];
  if (list.length === 0) return null;
  const caps = [...new Set(list.map((r) => r.cap))].sort((a, b) => a - b);
  return (
    <div id="enrichment-not-asked" className="scroll-mt-16">
      <Section title="Not asked by the enrichment" count={list.length}>
        <p className="mb-3 max-w-[75ch] text-sm text-text-secondary">
          The enrichment stopped at its lookup cap of {caps.join(", ")} per kind (the setting enrichment_max_lookups).
          A missing reputation, ASN or geography on these values means it was not asked, not that the value is clean.
        </p>
        <div {...scrollRegion("Values the enrichment did not ask about")} className={`-mx-4 -mb-3 overflow-x-auto ${SCROLL_REGION_FOCUS}`}>
          <table className="w-full">
            <thead>
              <tr className="border-b border-border-light">
                <Th>Value</Th>
                <Th>Kind</Th>
                <Th>Not asked</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {list.map((row, i) => (
                <tr key={`${row.kind}-${row.value}-${i}`}>
                  <td className="px-4 py-2 align-top font-mono text-xs text-status-blue break-all">{row.value}</td>
                  <td className="px-4 py-2 align-top text-xs text-text-secondary">{row.kind === "ip" ? "IP" : "Domain"}</td>
                  <td className="px-4 py-2 align-top text-xs text-text-secondary">
                    {row.questions.length > 0 ? row.questions.map((q) => QUESTION_WORDS[q] ?? q).join(", ") : "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
    </div>
  );
}
