import { describe, expect, it } from "vitest";

import type { AgentFinding } from "@/types";
import { hasRuleMatches, ruleMatches } from "../ruleMatches";

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

describe("what the panel draws", () => {
  it("reads a YARA claim for its rule, its patterns and its citation", () => {
    const { yara } = ruleMatches([layer("yara_layer", [YARA_CLAIM])]);
    expect(yara).toHaveLength(1);
    expect(yara[0].rule_name).toBe("sandbox_evasion");
    expect(yara[0].pattern_count).toBe(3);
    expect(yara[0].technique_id).toBe("T1497");
    expect(yara[0].evidence).toBe("ev_0007");
  });

  it("reads a Sigma claim for its rule, its technique, its source and its severity", () => {
    const { sigma } = ruleMatches([layer("sigma_layer", [SIGMA_CLAIM])]);
    expect(sigma).toHaveLength(1);
    expect(sigma[0].rule_name).toBe("Suspicious DNS Z Flag Bit Set");
    expect(sigma[0].technique_id).toBe("T1095");
    expect(sigma[0].source).toBe("generic");
    expect(sigma[0].severity).toBe("critical");
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
    expect(ruleMatches(undefined)).toEqual({ yara: [], sigma: [] });
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
