/**
 * The agents table shows every claim an agent made (T-439): the first leads
 * the Key Finding cell and the rest sit under a "+N more" disclosure, none
 * left out.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useParams: () => ({ id: "J1" }) }));

import type { AgentFindingDTO, ReportDetailDTO } from "@/lib/api";
import { AnalysisContext } from "../AnalysisContext";
import AgentsTab, { claimTexts } from "../AgentsPanel";

const finding = (over: Partial<AgentFindingDTO>): AgentFindingDTO => ({
  agent_name: "checker",
  domain: "generic",
  claims: [],
  dissent_items: null,
  revision_rounds: 1,
  final_confidence: 0.8,
  status: "complete",
  ...over,
});

function panelHtml(findings: AgentFindingDTO[]): string {
  const report = { agent_findings: findings, run_summary: null } as unknown as ReportDetailDTO;
  return renderToStaticMarkup(
    createElement(
      AnalysisContext.Provider,
      {
        value: { jobId: "J1", report, job: null, loading: false, reportError: null, showEvidence: null },
      },
      createElement(AgentsTab),
    ),
  );
}

describe("claimTexts", () => {
  it("reads every claim in order, whatever shape it has", () => {
    expect(
      claimTexts([
        { description: "packs with UPX" },
        { claim: "beacons to a host" },
        "a bare string",
        { confidence: 0.4 },
        7,
        null,
      ]),
    ).toEqual(["packs with UPX", "beacons to a host", "a bare string", '{"confidence":0.4}', "7"]);
  });

  it("reads no claims as none", () => {
    expect(claimTexts(null)).toEqual([]);
    expect(claimTexts([])).toEqual([]);
  });
});

describe("the agents table's Key Finding cell", () => {
  it("draws all 37 claims of an agent: the first in the cell, 36 under the disclosure", () => {
    const claims = Array.from({ length: 37 }, (_, i) => ({ description: `claim number ${i + 1}.` }));
    const html = panelHtml([finding({ claims })]);
    for (let i = 1; i <= 37; i++) expect(html, `claim ${i}`).toContain(`claim number ${i}.`);
    expect(html).toContain("<details");
    expect(html).toMatch(/\+36 more(<!-- -->)? claims/);
    expect(html.match(/<li\b/g)).toHaveLength(36);
  });

  it("says one more claim in the singular", () => {
    const html = panelHtml([finding({ claims: ["first", "second"] })]);
    expect(html).toMatch(/\+1 more(<!-- -->)? claim</);
  });

  it("draws no disclosure for a single claim", () => {
    const html = panelHtml([finding({ claims: ["only one"] })]);
    expect(html).toContain("only one");
    expect(html).not.toContain("<details");
  });

  it("keeps a non-complete agent's claims under its reason rather than dropping them", () => {
    const html = panelHtml([
      finding({ status: "timeout", status_reason: "ran out of time", claims: ["partial a", "partial b"] }),
    ]);
    expect(html).toContain("ran out of time");
    expect(html).toContain("partial a");
    expect(html).toContain("partial b");
    expect(html).toMatch(/\+2 more(<!-- -->)? claims/);
  });

  it("still says so when an agent recorded nothing", () => {
    const html = panelHtml([finding({ claims: null })]);
    expect(html).toContain("No specific findings recorded.");
    expect(html).not.toContain("<details");
  });
});
