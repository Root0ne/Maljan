/**
 * Text that quotes command lines and Windows paths is drawn as written: a
 * backslash, an asterisk or a dunder name survives literally, in the places
 * that hold a tool's or an agent's own words rather than the report model's
 * Markdown.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import AgentReport from "../AgentReport";
import { ArtifactSections } from "../ArtifactTable";
import TechnicalAnalysisPanel from "../TechnicalAnalysisPanel";
import { STRINGS_SECTION } from "./storedRunShapes";
import type { MalwareReport } from "@/types/malware-report";

const LITERAL = String.raw`C:\Users\*\AppData\Roaming\__init__.py and \\server\share\*.docx`;

// The literal holds none of the characters React escapes (& < > " '), so a
// literal drawn as written appears verbatim in the markup.

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
    expect(html.split(LITERAL)).toHaveLength(4);
    expect(html).not.toContain("<strong>init</strong>");
    expect(html).not.toContain("<em>");
  });

  it("keeps an analyst's claim as written, and its prose's backslashes through the Markdown", () => {
    const report = `[STATIC ANALYST — round 1]\nDomain: static | Mean confidence: 0.70\n  Claim 1: ${LITERAL} | Evidence: ev_0001 | Confidence: 0.90\n\nIt reads ${LITERAL}.`;
    const html = renderToStaticMarkup(createElement(AgentReport, { report, name: "Report of static" }));
    expect(text(html).split(LITERAL)).toHaveLength(3);
    expect(html).not.toContain("<strong>init</strong>");
    expect(html).toContain("(ev_0001)");
    expect(html).toContain("90%");
  });

  it("keeps a tool section's prose as written", () => {
    const html = renderToStaticMarkup(
      createElement(ArtifactSections, { sections: [{ ...STRINGS_SECTION, kind: "text", rows: [], items: [], text: LITERAL }] }),
    );
    expect(html).toContain(LITERAL);
  });
});
