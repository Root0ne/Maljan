import { describe, expect, it } from "vitest";

import {
  corroborationLists,
  associatedBy,
  corroborationSources,
  isCorroborated,
  orderedTactics,
  parseTechniques,
  tacticOrder,
} from "../capabilityHeatmap";

function row(over: Record<string, unknown> = {}) {
  return {
    technique_id: "T1055",
    technique_name: "Process Injection",
    tactic_id: "TA0005",
    contributing_layers: ["static", "dynamic"],
    ...over,
  };
}

function only(raw: unknown[]) {
  const [tactic] = parseTechniques(raw);
  return tactic.techniques[0];
}

describe("the judge as a source", () => {
  it("is not a badge beside the layers that observed the technique", () => {
    const tech = only([row({ contributing_layers: ["static", "judge"] })]);
    expect(tech.sources).toEqual(["static", "judge"]);
    expect(tech.corroborating).toEqual(["static"]);
  });

  it("does not corroborate what it read", () => {
    expect(isCorroborated(only([row({ contributing_layers: ["static", "judge"] })]))).toBe(
      false
    );
  });

  it("leaves a genuinely corroborated technique corroborated", () => {
    expect(
      isCorroborated(only([row({ contributing_layers: ["static", "dynamic", "judge"] })]))
    ).toBe(true);
  });

  it("is still shown as the source of a technique nothing else named", () => {
    const tech = only([row({ contributing_layers: ["judge"] })]);
    expect(tech.sources).toEqual(["judge"]);
    expect(tech.corroborating).toEqual([]);
    expect(isCorroborated(tech)).toBe(false);
  });

  it("is matched exactly, the way capability_matrix.py matches it", () => {
    // A layer name is a validated agent key, so `"Judge"` cannot arrive from
    // the pipeline. If one ever did, the backend would count it towards
    // `is_corroborated` — and the badge here has to say the same thing the
    // persisted flag says, even when both are wrong about the same row.
    expect(only([row({ contributing_layers: ["Judge", "static"] })]).corroborating).toEqual([
      "Judge",
      "static",
    ]);
    expect(only([row({ contributing_layers: ["judge", "static"] })]).corroborating).toEqual([
      "static",
    ]);
  });
});

describe("an id the catalog does not have", () => {
  it("keeps its row and is marked", () => {
    const tech = only([row({ technique_id_valid: false })]);
    expect(tech.id).toBe("T1055");
    expect(tech.valid).toBe(false);
  });

  it("is valid when the flag is absent, which is what an old row meant", () => {
    expect(only([row()]).valid).toBe(true);
  });

  it("stays marked when one of two merged rows was marked", () => {
    const tech = only([row({ technique_id_valid: false }), row({ technique_id_valid: true })]);
    expect(tech.valid).toBe(false);
  });
});

describe("merging two rows for the same technique", () => {
  it("sums the matches and takes the union of the layers", () => {
    const tech = only([
      row({ contributing_layers: ["static"] }),
      row({ contributing_layers: ["dynamic"] }),
    ]);
    expect(tech.sources).toEqual(["static", "dynamic"]);
    expect(tech.matches).toBe(2);
    expect(isCorroborated(tech)).toBe(true);
  });
});

describe("the columns", () => {
  it("read the canonical name for a known tactic id", () => {
    const [tactic] = parseTechniques([row({ tactic_name: "Stealth" })]);
    expect(tactic.name).toBe("Defense Evasion");
  });

  it("keep whatever name an unknown tactic supplied", () => {
    const [tactic] = parseTechniques([row({ tactic_id: "TA9999", tactic_name: "Something" })]);
    expect(tactic.name).toBe("Something");
  });

  it("come out in kill-chain order, with the unknown ones after", () => {
    const tactics = orderedTactics(
      parseTechniques([
        row({ tactic_id: "TA0040", technique_id: "T1486" }),
        row({ tactic_id: "TA9999", technique_id: "T9999" }),
        row({ tactic_id: "TA0001", technique_id: "T1566" }),
      ])
    );
    expect(tactics.map((t) => t.id)).toEqual(["TA0001", "TA0040", "TA9999"]);
  });

  it("sort an unrecognised id after every Enterprise one", () => {
    expect(tacticOrder("TA0001")).toBeLessThan(tacticOrder("TA9999"));
  });
});

describe("what the run summary recorded", () => {
  it("is the sources it listed for that technique", () => {
    expect(
      corroborationLists({ T1055: { asserted_by: ["capa"], claimed_by: ["static"] } }, "T1055")
    ).toEqual({ asserted_by: ["capa"], claimed_by: ["static"] });
    expect(
      corroborationSources({ T1055: { asserted_by: ["capa"], claimed_by: ["static"] } }, "T1055")
    ).toEqual(["capa", "static"]);
    // A summary stored before the two lists is read as claimed by all of them.
    expect(corroborationLists({ T1055: ["static", "dynamic"] }, "T1055")).toEqual({
      asserted_by: [],
      claimed_by: ["static", "dynamic"],
    });
    expect(corroborationSources({ T1055: ["static", "dynamic"] }, "T1055")).toEqual([
      "static",
      "dynamic",
    ]);
  });

  it("is nothing for a technique it has no row for", () => {
    expect(corroborationSources({}, "T1055")).toEqual([]);
    expect(corroborationSources(null, "T1055")).toEqual([]);
  });
});

describe("a technique the catalogue only associates", () => {
  it("names the catalogue while both source lists stay empty", () => {
    const rows = { T1113: { asserted_by: [], claimed_by: [], associated_by: ["api_capability"] } };
    expect(corroborationSources(rows, "T1113")).toEqual([]);
    expect(associatedBy(rows, "T1113")).toEqual(["api_capability"]);
  });

  it("is an empty list for a row without associations and for a missing row", () => {
    expect(associatedBy({ T1055: { asserted_by: ["capa"], claimed_by: [] } }, "T1055")).toEqual([]);
    expect(associatedBy({}, "T1113")).toEqual([]);
    expect(associatedBy(null, "T1113")).toEqual([]);
  });
});

describe("a technique the run did not publish", () => {
  it("carries the reason the check gave", () => {
    const tech = only([
      row({
        not_published:
          "TECHNIQUE T1055 belongs to the ATT&CK enterprise domain (platforms Linux, " +
          "Windows, macOS); this sample is mobile-domain, Android.",
      }),
    ]);
    expect(tech.notPublished).toContain("mobile-domain, Android");
  });

  it("is empty for a published mapping, which carries no such key", () => {
    expect(only([row()]).notPublished).toBe("");
  });

  it("keeps the reason when the same id arrives twice", () => {
    const tech = only([row(), row({ not_published: "outside the sample's ATT&CK domain" })]);
    expect(tech.notPublished).toBe("outside the sample's ATT&CK domain");
  });
});
