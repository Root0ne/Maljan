import { describe, expect, it } from "vitest";

import type { AgentFinding } from "@/types";
import type { EvidenceSection } from "@/types/malware-report";
import { hasRuleMatches, orderByLevel, ruleMatches } from "../ruleMatches";

function layer(name: string, claims: unknown[]): AgentFinding {
  return {
    agent_name: name,
    domain: "static",
    claims,
    dissent_items: null,
    revision_rounds: 0,
    final_confidence: 1,
    status: "complete",
  };
}

const YARA_CLAIM = {
  claim:
    "Deterministic YARA signature match: Virtualization and sandbox evasion " +
    "(rule: sandbox_evasion, 3 pattern(s) found)",
  confidence: 0.8,
  evidence_ref: "ev_0007",
  technique_id: "T1497",
};

const SIGMA_CLAIM = {
  claim: "Sigma rule detection: Suspicious DNS Z Flag Bit Set (technique T1095, source=generic)",
  confidence: 0.95,
  evidence_ref: "ev_0008",
  technique_id: "",
};

function section(key: string, columns: string[], rows: string[][]): EvidenceSection {
  return {
    key,
    title: key,
    kind: "table",
    columns,
    rows,
    text: "",
    items: [],
    evidence_ids: ["ev_0100"],
    source: "tool",
  };
}

const SIGMA_SECTION_ROWS = section(
  "sigma_matches",
  ["Rule", "Level", "Technique", "Matched fields"],
  [
    ["Run key persistence", "high", "T1547.001", "TargetObject=HKCU\\Run\\x"],
    ["Encoded PowerShell", "Medium", "T1059.001", "CommandLine=-enc"],
    ["Untitled", "-", "-", "-"],
  ],
);

const YARA_SECTION_ROWS = section("yara_matches", ["Rule", "Tags", "Where"], [
  ["UPX_packed", "packer", "0x400"],
]);

describe("what the panel draws", () => {
  it("reads a YARA claim for its rule, its patterns and its citation", () => {
    const { yara } = ruleMatches([layer("yara_layer", [YARA_CLAIM])]);
    expect(yara).toHaveLength(1);
    expect(yara[0].rule_name).toBe("sandbox_evasion");
    expect(yara[0].pattern_count).toBe(3);
    expect(yara[0].technique_id).toBe("T1497");
    expect(yara[0].evidence).toBe("ev_0007");
  });

  it("reads a stored Sigma claim for its rule, technique and source, and records no level", () => {
    // The shape every run before the layer carried the rule's level stored.
    // Its 0.95 is the rule's maturity status as a number; it is not read as a
    // severity, so no level is invented from it.
    const { sigma } = ruleMatches([layer("sigma_layer", [SIGMA_CLAIM])]);
    expect(sigma).toHaveLength(1);
    expect(sigma[0].rule_name).toBe("Suspicious DNS Z Flag Bit Set");
    expect(sigma[0].technique_id).toBe("T1095");
    expect(sigma[0].source).toBe("generic");
    expect(sigma[0].confidence).toBeCloseTo(0.95);
    expect(sigma[0].level).toBeNull();
  });

  it("takes a level the claim object carries as a field", () => {
    const { sigma } = ruleMatches([layer("sigma_layer", [{ ...SIGMA_CLAIM, level: "Critical" }])]);
    expect(sigma[0].level).toBe("critical");
  });

  it("reads a current run's Sigma section, with each rule's own level", () => {
    // The stored shape of a new report: `sigma_matches`, built from the rule
    // tool's ledger rows, beside the old layer's claims it takes over from.
    const { sigma } = ruleMatches([layer("sigma_layer", [SIGMA_CLAIM])], [SIGMA_SECTION_ROWS]);
    expect(sigma.map((r) => r.rule_name)).toEqual([
      "Run key persistence",
      "Encoded PowerShell",
      "Untitled",
    ]);
    expect(sigma[0]).toMatchObject({
      level: "high",
      technique_id: "T1547.001",
      evidence: "TargetObject=HKCU\\Run\\x",
      confidence: null,
      recorded: true,
    });
    // A rule that declares no level is not one whose level went unrecorded.
    expect(sigma[2]).toMatchObject({ level: null, recorded: true });
  });

  it("keeps the section a kind was read from, so its rows cite their ledger entries", () => {
    const read = ruleMatches([], [SIGMA_SECTION_ROWS, YARA_SECTION_ROWS]);
    expect(read.sigmaSection?.evidence_ids).toEqual(["ev_0100"]);
    expect(read.yaraSection?.key).toBe("yara_matches");
    const old = ruleMatches([layer("sigma_layer", [SIGMA_CLAIM])], []);
    expect(old.sigmaSection).toBeNull();
  });

  it("marks an old run's claim rows as recording no level", () => {
    const { sigma } = ruleMatches([layer("sigma_layer", [SIGMA_CLAIM])], []);
    expect(sigma[0]).toMatchObject({ level: null, recorded: false });
  });

  it("reads a current run's YARA section, and ignores an empty one", () => {
    const { yara } = ruleMatches([layer("yara_layer", [YARA_CLAIM])], [YARA_SECTION_ROWS]);
    expect(yara).toEqual([
      {
        rule_name: "UPX_packed",
        pattern_count: 0,
        technique_id: "",
        evidence: "0x400",
        tags: "packer",
        confidence: null,
      },
    ]);
    const empty = { ...YARA_SECTION_ROWS, rows: [] };
    expect(ruleMatches([layer("yara_layer", [YARA_CLAIM])], [empty]).yara[0].rule_name).toBe(
      "sandbox_evasion",
    );
    expect(hasRuleMatches([], [SIGMA_SECTION_ROWS])).toBe(true);
  });

  it("orders levels by the ladder and leaves rows without one out of that sort", () => {
    const rows = [
      ["no-level", "-", "", ""],
      ["low-one", "low", "", ""],
      ["critical-one", "critical", "", ""],
      ["medium-one", "medium", "", ""],
    ];
    const { sigma } = ruleMatches([], [{ ...SIGMA_SECTION_ROWS, rows }]);
    expect(orderByLevel(sigma).map((r) => r.rule_name)).toEqual([
      "critical-one",
      "medium-one",
      "low-one",
      "no-level",
    ]);
  });

  it("takes the first finding of a layer and not a second recording of it", () => {
    const { yara } = ruleMatches([
      layer("yara_layer", [YARA_CLAIM]),
      layer("yara_layer", [YARA_CLAIM, YARA_CLAIM]),
    ]);
    expect(yara).toHaveLength(1);
  });
});

describe("what the panel cannot draw", () => {
  it("keeps nothing from a claims array of plain strings", () => {
    /* The shape the console tolerates elsewhere and this panel cannot read: a
     * bare string carries no rule name, no technique and nothing to cite. The
     * tab rule reads the same answer, so the tab is not offered over a heading
     * with nothing under it. */
    const strings = [layer("yara_layer", ["Deterministic YARA signature match: evasion"])];
    expect(ruleMatches(strings).yara).toEqual([]);
    expect(hasRuleMatches(strings)).toBe(false);
  });

  it("keeps nothing from a layer with an empty or absent claims list", () => {
    expect(hasRuleMatches([layer("yara_layer", [])])).toBe(false);
    expect(hasRuleMatches([{ ...layer("sigma_layer", []), claims: null }])).toBe(false);
  });

  it("ignores every finding that is not one of the two layers", () => {
    expect(hasRuleMatches([layer("static", [YARA_CLAIM])])).toBe(false);
  });

  it("answers for nothing at all", () => {
    expect(hasRuleMatches(null)).toBe(false);
    expect(ruleMatches(undefined)).toEqual({
      yara: [],
      sigma: [],
      yaraSection: null,
      sigmaSection: null,
    });
  });
});

describe("what the panel does draw", () => {
  it("says so for either layer on its own", () => {
    expect(hasRuleMatches([layer("yara_layer", [YARA_CLAIM])])).toBe(true);
    expect(hasRuleMatches([layer("sigma_layer", [SIGMA_CLAIM])])).toBe(true);
  });

  it("keeps the object-shaped claims of a list that also holds strings", () => {
    const mixed = [layer("yara_layer", ["a string", YARA_CLAIM])];
    expect(ruleMatches(mixed).yara).toHaveLength(1);
    expect(hasRuleMatches(mixed)).toBe(true);
  });
});
