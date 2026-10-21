import { describe, expect, it } from "vitest";

import type { AgentFindingDTO, ReportDetailDTO } from "@/lib/api";
import type { JobRoster } from "@/types";
import type { EvidenceSection, MalwareReport } from "@/types/malware-report";
import { TABS, tabHasContent, tabsFor } from "../analysisTabs";
import {
  agentsOfSource,
  extraTabs,
  tabByParam,
  unroutedSections,
} from "../extraTabs";
import { tabOfSection, unrenderedSections } from "../reportSections";

function section(over: Partial<EvidenceSection> = {}): EvidenceSection {
  return {
    key: "tool_analyze_file",
    title: "Analyze file",
    kind: "table",
    columns: ["Field", "Value"],
    rows: [["packer", "upx"]],
    text: "",
    items: [],
    evidence_ids: ["ev_0001"],
    source: "tool:analyze_file",
    source_server: "qu1cksc0pe",
    ...over,
  };
}

function finding(
  agent: string,
  domain: string,
  claims: number,
): AgentFindingDTO {
  return {
    agent_name: agent,
    domain,
    claims: Array.from({ length: claims }, (_, i) => ({
      claim: `claim ${i}`,
      confidence: 0.7,
    })),
    dissent_items: null,
    revision_rounds: 0,
    final_confidence: 0.7,
    status: "complete",
  };
}

/** The roster of the stored runs: built-ins plus two operator generic agents. */
const ROSTER: JobRoster = {
  agents: [
    { key: "triage", label: "Triage", role: "generic", stages: ["triage"] },
    {
      key: "static",
      label: "Static analyst",
      role: "static",
      stages: ["analysis"],
    },
    {
      key: "all_tools_static_r2",
      label: "R2",
      role: "static",
      stages: ["analysis"],
    },
    {
      key: "all_tools_qu1cksc0pe",
      label: "Quick Scope",
      role: "generic",
      stages: ["analysis"],
    },
    {
      key: "all_tools_reverser_ghidra",
      label: "Reverser",
      role: "generic",
      stages: ["reversing"],
    },
    {
      key: "dynamic",
      label: "Dynamic analyst",
      role: "dynamic",
      stages: ["analysis"],
    },
    {
      key: "network",
      label: "Network analyst",
      role: "network",
      stages: ["analysis"],
    },
    { key: "judge", label: "Judge", role: "judge", stages: ["verdict"] },
    { key: "reporter", label: "Reporter", role: "report", stages: ["report"] },
  ],
  stages: [
    { key: "triage", label: "Triage", kind: "triage", agents: ["triage"] },
    {
      key: "analysis",
      label: "Analysis",
      kind: "analysis",
      agents: [
        "static",
        "all_tools_static_r2",
        "all_tools_qu1cksc0pe",
        "dynamic",
        "network",
      ],
    },
    {
      key: "reversing",
      label: "Reversing",
      kind: "analysis",
      agents: ["all_tools_reverser_ghidra"],
    },
    { key: "verdict", label: "Verdict", kind: "verdict", agents: ["judge"] },
    { key: "report", label: "Report", kind: "report", agents: ["reporter"] },
  ],
};

function report(
  sections: EvidenceSection[],
  findings: AgentFindingDTO[],
  placed: Record<string, string> | null = null,
): ReportDetailDTO {
  return {
    id: "r",
    job_id: "j",
    verdict: "Malware",
    overall_confidence: 0.8,
    malware_category: null,
    stix_bundle: null,
    mitre_techniques: null,
    agent_reports: null,
    negotiation_log: null,
    run_summary: null,
    agent_findings: findings,
    malware_report: { sections } as unknown as MalwareReport,
    section_tabs: placed,
    created_at: "2026-10-13T10:00:00Z",
  };
}

const keys = (tabs: { key: string }[]) => tabs.map((t) => t.key);

describe("an operator agent's tab", () => {
  it("holds all of its claims, not only the first, and is named after the agent", () => {
    const tabs = extraTabs(
      [],
      null,
      [finding("all_tools_reverser_ghidra", "all_tools_reverser_ghidra", 58)],
      ROSTER,
    );
    expect(tabs).toHaveLength(1);
    expect(tabs[0].label).toBe("Reverser");
    expect(tabs[0].key).toBe("/agent/all_tools_reverser_ghidra");
    expect(tabs[0].claims?.claims).toHaveLength(58);
  });

  it("is not offered for a built-in, whatever it said", () => {
    const said = [
      "triage",
      "static",
      "dynamic",
      "network",
      "judge",
      "reporter",
      "all_tools_static_r2",
    ].map((key) => finding(key, key, 3));
    expect(extraTabs([], null, said, ROSTER)).toEqual([]);
  });

  it("is not offered without content, or without a roster that names the agent", () => {
    expect(
      extraTabs([], null, [finding("all_tools_qu1cksc0pe", "x", 0)], ROSTER),
    ).toEqual([]);
    expect(
      extraTabs([], null, [finding("all_tools_qu1cksc0pe", "x", 2)], null),
    ).toEqual([]);
  });

  it("does not draw claims DYNAMIC already draws", () => {
    const said = [finding("all_tools_qu1cksc0pe", "dynamic", 2)];
    expect(extraTabs([], null, said, ROSTER)).toEqual([]);
  });

  it("takes the sections it is named as the author of, from a merged artifact source", () => {
    const own = section({
      key: "artifact_oddity",
      source: "artifact:static, all_tools_qu1cksc0pe",
      source_server: null,
    });
    expect(agentsOfSource(own.source)).toEqual([
      "static",
      "all_tools_qu1cksc0pe",
    ]);
    const tabs = extraTabs([own], null, [], ROSTER);
    expect(tabs.map((t) => [t.kind, t.id, t.sections.length])).toEqual([
      ["agent", "all_tools_qu1cksc0pe", 1],
    ]);
  });
});

describe("a tool server's tab", () => {
  it("is named after the server and holds the sections no fixed tab draws", () => {
    const sections = [
      section(),
      section({ key: "tool_detect_packer", evidence_ids: ["ev_0002"] }),
      section({ key: "tool_other", source_server: "ghidra" }),
    ];
    const tabs = extraTabs(sections, null, [], ROSTER);
    expect(tabs.map((t) => [t.kind, t.label, t.sections.length])).toEqual([
      ["server", "qu1cksc0pe", 2],
      ["server", "ghidra", 1],
    ]);
    expect(tabs[0].key).toBe("/server/qu1cksc0pe");
  });

  it("never takes a section a fixed tab draws, by key or by the report's placement", () => {
    const sections = [
      section({ key: "pe_imports", source_server: "analysis" }),
      section({ key: "tool_placed", source_server: "qu1cksc0pe" }),
    ];
    expect(extraTabs(sections, { tool_placed: "dynamic" }, [], ROSTER)).toEqual(
      [],
    );
  });

  it("skips an empty section and a section with no single server", () => {
    const sections = [
      section({ rows: [] }),
      section({ key: "tool_mixed", source_server: null }),
    ];
    expect(extraTabs(sections, null, [], ROSTER)).toEqual([]);
  });
});

describe("the EVIDENCE footer", () => {
  it("keeps only what no tab draws", () => {
    const sections = [
      section(),
      section({ key: "tool_mixed", source_server: null }),
      section({ key: "pe_imports" }),
    ];
    expect(
      unroutedSections(sections, null, [], ROSTER).map((s) => s.key),
    ).toEqual(["tool_mixed"]);
    // Without the new routing the footer was every section no fixed tab draws.
    expect(unrenderedSections(sections, null).map((s) => s.key)).toEqual([
      "tool_analyze_file",
      "tool_mixed",
    ]);
  });
});

describe("tabsFor with a stored run", () => {
  // A stored run: no `source_server` on its sections, no tab placements.
  const stored = report(
    [
      section({ source_server: undefined }),
      section({ key: "tool_x", source_server: undefined }),
    ],
    [finding("all_tools_qu1cksc0pe", "all_tools_qu1cksc0pe", 12)],
  );

  it("keeps the fixed twelve in their order and appends an agent tab after them", () => {
    const tabs = tabsFor(stored, ROSTER);
    const fixed = keys(tabs).filter(
      (k) => !k.startsWith("/agent") && !k.startsWith("/server"),
    );
    expect(fixed).toEqual(
      TABS.map((t) => t.key).filter((k) => fixed.includes(k)),
    );
    expect(keys(tabs).slice(-1)).toEqual(["/agent/all_tools_qu1cksc0pe"]);
    expect(tabs.find((t) => t.key.startsWith("/agent"))?.group).toBe("extra");
  });

  it("adds a server tab once the section says its server", () => {
    const served = report(
      [section()],
      [finding("all_tools_qu1cksc0pe", "all_tools_qu1cksc0pe", 12)],
    );
    expect(keys(tabsFor(served, ROSTER)).slice(-2)).toEqual([
      "/agent/all_tools_qu1cksc0pe",
      "/server/qu1cksc0pe",
    ]);
  });

  it("adds nothing before there is a report", () => {
    expect(keys(tabsFor(null, ROSTER))).toEqual([
      "",
      "/conversation",
      "/evidence",
    ]);
  });
});

describe("tabOfSection for the stored runs' operator sections", () => {
  it("still places tool_* keys nowhere, so the new tabs only take what was unplaced", () => {
    expect(tabOfSection("tool_analyze_file")).toBe("other");
    expect(
      tabOfSection("tool_analyze_file", { tool_analyze_file: "static" }),
    ).toBe("static");
    expect(
      tabOfSection("tool_analyze_file", { tool_analyze_file: "nonsense" }),
    ).toBe("other");
  });
});

describe("a server named like a fixed tab", () => {
  it("draws no server tab for a section the report placed on a built-in author's tab", () => {
    const flows = section({ key: "tool_flows", source_server: "network" });
    expect(extraTabs([flows], { tool_flows: "network" }, [], ROSTER)).toEqual(
      [],
    );
  });

  it("is told apart from the fixed tab and from an agent of the same name", () => {
    const sections = [
      section({ key: "tool_a", source_server: "network" }),
      section({ key: "tool_b", source_server: "Quick Scope" }),
    ];
    const tabs = tabsFor(
      report(sections, [finding("all_tools_qu1cksc0pe", "x", 1)]),
      ROSTER,
    ).filter((t) => t.group === "extra");
    expect(tabs.map((t) => t.label)).toEqual([
      "Quick Scope (agent)",
      "network (server)",
      "Quick Scope (server)",
    ]);
  });
});

describe("the route key of an extra tab", () => {
  const spaced = section({ key: "tool_a", source_server: "my server" });
  const percent = section({ key: "tool_b", source_server: "50%" });
  const dots = section({ key: "tool_c", source_server: ".." });
  const tabs = extraTabs([spaced, percent, dots], null, [], ROSTER);

  it("encodes the id, a dots-only one included", () => {
    expect(tabs.map((t) => t.key)).toEqual([
      "/server/my%20server",
      "/server/50%25",
      "/server/%2E%2E",
    ]);
  });

  it("matches the param as handed over or decoded, and decodes only once", () => {
    expect(tabByParam(tabs, "server", "my%20server")?.id).toBe("my server");
    expect(tabByParam(tabs, "server", "my server")?.id).toBe("my server");
    expect(tabByParam(tabs, "server", "50%25")?.id).toBe("50%");
    expect(tabByParam(tabs, "server", "50%")?.id).toBe("50%");
    expect(tabByParam(tabs, "server", "..")?.id).toBe("..");
    expect(tabByParam(tabs, "agent", "my%20server")).toBeUndefined();
    expect(tabByParam(tabs, "server", "50%2525")).toBeUndefined();
  });
});

describe("a run with no operator agent or server", () => {
  it("offers exactly what it offered before the extra tabs", () => {
    const run = report(
      [section({ key: "pe_imports", source_server: "analysis" })],
      [finding("static", "static", 3), finding("triage", "triage", 2)],
    );
    expect(tabsFor(run, ROSTER)).toEqual(
      TABS.filter((tab) => tabHasContent(tab.key, run, ROSTER)),
    );
  });
});
