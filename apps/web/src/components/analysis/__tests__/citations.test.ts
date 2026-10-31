import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import AnalystFindings from "../AnalystFindings";
import EvidenceChips from "../EvidenceChips";
import { citationParts, isEvidenceId } from "../citations";
import { UNDISCUSSED } from "./storedRunShapes";

const JOB = "job-1";
const links = (html: string) =>
  [...html.matchAll(/href="([^"]*)"/g)].map((m) => decodeURIComponent(m[1]));
const chips = (ids: string[]) =>
  renderToStaticMarkup(createElement(EvidenceChips, { ids, jobId: JOB }));

describe("a citation split into its ids and its words (T-332)", () => {
  it("finds each id and keeps every character between them", () => {
    const ref = UNDISCUSSED[0].evidence_ref!;
    const parts = citationParts(ref);
    expect(parts).toEqual([
      { kind: "id", id: "ev_0024" },
      { kind: "text", text: " (row 0x3868), " },
      { kind: "id", id: "ev_0019" },
      { kind: "text", text: "." },
    ]);
    expect(parts.map((p) => (p.kind === "id" ? p.id : p.text)).join("")).toBe(ref);
  });

  it("tells a bare id from prose that names one", () => {
    expect(isEvidenceId("ev_0004")).toBe(true);
    expect(isEvidenceId(" ev_0004 ")).toBe(true);
    expect(isEvidenceId("ev_0004.")).toBe(false);
    expect(isEvidenceId("ev_0024 (row 0x3868), ev_0019.")).toBe(false);
  });
});

describe("the chips of an analyst's evidence reference (T-332)", () => {
  it("draws one link per id, each to its own entry", () => {
    const html = chips([UNDISCUSSED[0].evidence_ref!]);
    expect(links(html)).toEqual([
      `/analysis/${JOB}/evidence/records?evidence=ev_0024`,
      `/analysis/${JOB}/evidence/records?evidence=ev_0019`,
    ]);
    expect(html).toContain(" (row 0x3868), ");
    // Inline, so the prose keeps the spaces it was written with.
    expect(html).not.toContain("inline-flex flex-wrap items-center gap-1\"><a");
    expect(html).toMatch(/ev_0019<\/a><span>\.<\/span>/);
  });

  it("keeps a semicolon-separated reference's prose as words", () => {
    const html = chips([UNDISCUSSED[1].evidence_ref!]);
    expect(links(html).map((href) => href.split("evidence=")[1])).toEqual([
      "ev_0138",
      "ev_0134",
      "ev_0004",
    ]);
    expect(html).toContain("(packed flag, matched rule, string_hits 0); ");
    expect(html).toContain("(no special-artifact pattern); ");
    // No link carries the prose in its target.
    for (const href of links(html)) expect(href).toMatch(/evidence=ev_\d+$/);
  });

  it("draws a reference that names no id as words, not as a link", () => {
    const html = chips(["IAT: KERNEL32.dll!VirtualAllocEx"]);
    expect(links(html)).toEqual([]);
    expect(html).toContain("IAT: KERNEL32.dll!VirtualAllocEx");
  });

  it("draws a list of bare ids as it always has", () => {
    const html = chips(["ev_0001", "ev_0003", "ev_0004"]);
    expect(links(html)).toHaveLength(3);
    expect(html).toContain(">ev_0003</a>");
  });
});

describe("an analyst's claim card (T-332)", () => {
  it("links each id of its evidence reference", () => {
    const html = renderToStaticMarkup(
      createElement(AnalystFindings, {
        findings: [
          {
            agent: "triage",
            claims: [
              {
                claim: "The sample is not packed.",
                confidence: 0.8,
                evidence_ref: "ev_0004, ev_0020 (encoded blobs in the data sections).",
              },
            ],
          },
        ],
      }),
    );
    expect(links(html).map((href) => href.split("evidence=")[1])).toEqual(["ev_0004", "ev_0020"]);
    expect(html).toContain(" (encoded blobs in the data sections).");
  });
});
