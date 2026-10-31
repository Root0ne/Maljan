/**
 * Text that quotes command lines and Windows paths is drawn as written: a
 * backslash, an asterisk or a dunder name survives literally, in the places
 * that hold a tool's or an agent's own words rather than the report model's
 * Markdown.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { ArtifactSections } from "../ArtifactTable";
import TechnicalAnalysisPanel from "../TechnicalAnalysisPanel";
import { STRINGS_SECTION } from "./storedRunShapes";
import type { MalwareReport } from "@/types/malware-report";

const LITERAL = String.raw`C:\Users\*\AppData\Roaming\__init__.py and \\server\share\*.docx`;

/** What React escapes in markup, undone, so the literal can be compared. */
function text(html: string): string {
  return html.replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#x27;/g, "'");
}

describe("literal text", () => {
  it("keeps a step, an identifier's purpose and a command's description as written", () => {
    const report = {
      technical_analysis: {
        execution_flow: [{ order: 1, action: LITERAL, voice: "assessed", evidence_refs: [] }],
        host_identifiers: [{ kind: "path", value: "x", purpose: LITERAL, evidence_refs: [] }],
        commands: [{ id: "1", name: "run", description: LITERAL, evidence_refs: [] }],
      },
    } as unknown as MalwareReport;
    const html = renderToStaticMarkup(createElement(TechnicalAnalysisPanel, { report }));
    expect(text(html).split(LITERAL)).toHaveLength(4);
    expect(html).not.toContain("<strong>init</strong>");
    expect(html).not.toContain("<em>");
  });

  it("keeps a tool section's prose as written", () => {
    const html = renderToStaticMarkup(
      createElement(ArtifactSections, { sections: [{ ...STRINGS_SECTION, kind: "text", rows: [], items: [], text: LITERAL }] }),
    );
    expect(text(html)).toContain(LITERAL);
  });
});
