"use client";

import Section from "@/components/ui/Section";
import Th from "@/components/ui/Th";
import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import type { DirectedText } from "@/types/malware-report";
import { CiteMark } from "./CitedProse";

/** Each directed-text family in words (`analysis.directed_text.FAMILIES`). */
const FAMILY_WORDS: Record<string, string> = {
  override: "Instruction override",
  persona: "AI persona",
  verdict: "Verdict asked for",
  role_marker: "Chat role marker",
  tool_call: "Tool call written out",
  address: "Addressed to an AI or analyst",
};

/**
 * The phrases the sample carries that are written for whoever examines it
 * rather than for the machine it runs on: an instruction override, a persona
 * handed to a model, a verdict asked for, a chat role marker, a tool call
 * written out, words addressed to an AI or an analyst. Each is evidence about
 * the sample like any string it holds, and a fact about the run's safety: a
 * model shown it might follow it. None moves the verdict.
 *
 * The phrase is the triage pack's normalised, escaped form and is shown
 * exactly as held. The block keeps its place on every report and says when
 * none was recorded.
 */
export default function DirectedTextBlock({ rows }: { rows: readonly DirectedText[] | null | undefined }) {
  const list = rows ?? [];
  return (
    <div id="directed-text" className="scroll-mt-16">
      <Section title="Text written for an AI or an analyst" count={list.length || null} empty={list.length === 0} emptyText="None recorded">
        <p className="mb-3 max-w-[75ch] text-sm text-text-secondary">
          Phrases in the sample addressed to a model or an analyst reading it. A model shown one might follow it; none
          of them moves the verdict.
        </p>
        <div {...scrollRegion("Text written for an AI or an analyst")} className={`-mx-4 -mb-3 overflow-x-auto ${SCROLL_REGION_FOCUS}`}>
          <table className="w-full">
            <thead>
              <tr className="border-b border-border-light">
                <Th>Kind</Th>
                <Th>Phrase</Th>
                <Th>Times</Th>
                <Th>First seen at</Th>
                <Th>Evidence</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-light">
              {list.map((row, i) => (
                <tr key={`${row.family}-${i}`}>
                  <td className="px-4 py-2 align-top text-xs text-text-primary">
                    {FAMILY_WORDS[row.family] ?? row.family}
                    {(row.disguises ?? []).length > 0 && (
                      <span className="block text-text-muted">Disguised: {(row.disguises ?? []).join(", ")}</span>
                    )}
                    {(row.inside_template ?? 0) > 0 && (
                      <span className="block text-text-muted">{row.inside_template} inside a chat template</span>
                    )}
                  </td>
                  <td className="max-w-[28rem] px-4 py-2 align-top font-mono text-xs whitespace-pre-wrap break-all text-text-primary">
                    {row.text}
                  </td>
                  <td className="px-4 py-2 align-top text-xs text-text-secondary tabular-nums">{row.count ?? 1}</td>
                  <td className="px-4 py-2 align-top text-xs text-text-secondary break-words">{row.where || "-"}</td>
                  <td className="px-4 py-2 align-top text-xs text-text-muted">{row.evidence_id ? <CiteMark ids={[row.evidence_id]} title="The triage pack record of this phrase" named /> : "-"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
    </div>
  );
}
