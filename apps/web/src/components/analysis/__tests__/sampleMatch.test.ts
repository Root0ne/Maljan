import { describe, expect, it } from "vitest";

import type { DetectionRule } from "@/types/malware-report";
import { ruleStanding, sampleMatchBadge } from "../sampleMatch";

const SAID = "Run against the sample it was drafted from: ";

function rule(extra: Partial<DetectionRule> = {}): DetectionRule {
  return {
    kind: "yara",
    name: "Maljan_AutoGen_Example",
    body: "rule Maljan_AutoGen_Example { condition: true }",
    auto_generated: true,
    source_evidence: [],
    compile_error: null,
    ...extra,
  };
}

const TWO_STRINGS = [
  { identifier: "$s0", offset: 8000 },
  { identifier: "$s1", offset: null },
];

describe("a drafted rule checked against its own sample", () => {
  it("is green when its strings match, with each first offset and the strings found nowhere", () => {
    const badge = sampleMatchBadge(
      rule({
        matches_sample: true,
        matched_by: ["strings"],
        sample_strings: [
          { identifier: "$s0", offset: 8000 },
          { identifier: "$s1", offset: null },
          { identifier: "$s2", offset: 0 },
        ],
      }),
    );
    expect(badge).toEqual({
      label: "its strings match its sample",
      tone: "strings",
      detail:
        `${SAID}its strings match it (2 of 3 strings found). ` +
        "Found in the sample (first match of each): $s0 at 0x1f40, $s2 at 0x0. " +
        "Found nowhere in the sample: $s1.",
    });
  });

  it("names the hash clauses that held beside the strings", () => {
    const one = sampleMatchBadge(
      rule({
        matches_sample: true,
        matched_by: ["sha256", "strings"],
        sample_strings: [{ identifier: "$s0", offset: 16 }],
      }),
    );
    expect(one?.tone).toBe("strings");
    expect(one?.detail).toBe(
      `${SAID}its strings match it (1 of 1 strings found), and so does its sha256. ` +
        "Found in the sample (first match of each): $s0 at 0x10.",
    );
    const both = sampleMatchBadge(
      rule({
        matches_sample: true,
        matched_by: ["sha256", "imphash", "strings"],
        sample_strings: [{ identifier: "$s0", offset: 16 }],
      }),
    );
    expect(both?.detail).toContain("and so do its sha256 and imphash.");
  });

  it("is amber when it matches by a hash only and its strings do not", () => {
    const badge = sampleMatchBadge(
      rule({ matches_sample: true, matched_by: ["sha256"], sample_strings: TWO_STRINGS }),
    );
    expect(badge).toEqual({
      label: "matches its sample by hash only",
      tone: "hash",
      detail:
        `${SAID}the rule matches it by its sha256 only; its strings do not (1 of 2 strings found). ` +
        "Found in the sample (first match of each): $s0 at 0x1f40. " +
        "Found nowhere in the sample: $s1.",
    });
    const imphash = sampleMatchBadge(
      rule({ matches_sample: true, matched_by: ["imphash"], sample_strings: TWO_STRINGS }),
    );
    expect(imphash?.tone).toBe("hash");
    expect(imphash?.detail).toContain("the rule matches it by its imphash only;");
  });

  it("says a draft with no strings declares none", () => {
    const badge = sampleMatchBadge(
      rule({ matches_sample: true, matched_by: ["sha256", "imphash"], sample_strings: [] }),
    );
    expect(badge?.label).toBe("matches its sample by hash only");
    expect(badge?.detail).toBe(
      `${SAID}the rule matches it by its sha256 and imphash only; the draft declares no strings.`,
    );
  });

  it("is red when no clause held", () => {
    const badge = sampleMatchBadge(
      rule({ matches_sample: false, matched_by: [], sample_strings: TWO_STRINGS }),
    );
    expect(badge?.label).toBe("does not match its sample");
    expect(badge?.tone).toBe("misses");
    expect(badge?.detail).toBe(
      `${SAID}the rule does not match it (1 of 2 strings found). ` +
        "Found in the sample (first match of each): $s0 at 0x1f40. " +
        "Found nowhere in the sample: $s1.",
    );
    const bare = sampleMatchBadge(rule({ matches_sample: false, matched_by: [], sample_strings: [] }));
    expect(bare?.detail).toBe(`${SAID}the rule does not match it.`);
  });

  it("says why a rule was not checked, in a muted tone", () => {
    const badge = sampleMatchBadge(
      rule({ sample_not_checked: "the sample could not be read (No such file or directory)" }),
    );
    expect(badge).toEqual({
      label: "not run on its sample",
      tone: "neutral",
      detail:
        "Not run against the sample it was drafted from: " +
        "the sample could not be read (No such file or directory).",
    });
  });

  it("says only whether it matched when the record does not say which clause held", () => {
    expect(sampleMatchBadge(rule({ matches_sample: true, sample_strings: [] }))).toEqual({
      label: "matches its sample",
      tone: "neutral",
      detail: `${SAID}the rule matches it.`,
    });
    expect(sampleMatchBadge(rule({ matches_sample: false }))?.tone).toBe("misses");
  });

  it("draws nothing for a rule stored before the check, or a draft no engine runs on a file", () => {
    expect(sampleMatchBadge(rule())).toBeNull();
    expect(sampleMatchBadge(rule({ kind: "sigma" }))).toBeNull();
    expect(sampleMatchBadge(rule({ kind: "suricata" }))).toBeNull();
    // A stored report served with explicit nulls reads the same way.
    expect(
      sampleMatchBadge({
        ...rule(),
        matches_sample: null,
        matched_by: null,
        sample_strings: null,
        sample_not_checked: null,
      } as unknown as DetectionRule),
    ).toBeNull();
  });
});

// The haiku8 YARA draft as its record now carries it: its sha256 and import
// hash held, none of its five strings, and the analyst report's sentence for it.
const HAIKU8_STANDING =
  "Not printed in the analyst report: it matches the sample by its sha256 and imphash only, " +
  "not by its content; its body is in the evidence bundle.";
const HAIKU8 = rule({
  name: "Maljan_AutoGen_Latrodectus",
  matches_sample: true,
  matched_by: ["sha256", "imphash"],
  sample_strings: ["$s0", "$s1", "$s2", "$s3", "$s4"].map((identifier) => ({ identifier, offset: null })),
  printed: false,
  standing: HAIKU8_STANDING,
});

describe("what the analyst report says of a drafted rule", () => {
  it("is the sentence the record carries, as it carries it", () => {
    expect(ruleStanding(HAIKU8)).toEqual({ printed: false, sentence: HAIKU8_STANDING });
    const precision =
      "Precision: it selects on values this run publishes or a sandbox recorded; not run against " +
      "any other log (no retro-hunt), so how often it fires elsewhere is not measured.";
    expect(ruleStanding(rule({ kind: "sigma", printed: true, standing: precision }))).toEqual({
      printed: true,
      sentence: precision,
    });
  });

  it("keeps only the badge on a rule stored before the record carried it", () => {
    const stored = { ...HAIKU8, printed: undefined, standing: undefined };
    expect(ruleStanding(stored)).toBeNull();
    expect(sampleMatchBadge(stored)?.label).toBe("matches its sample by hash only");
    expect(ruleStanding(rule({ kind: "sigma" }))).toBeNull();
    // A stored report served with explicit nulls, or a half-written record, reads the same way.
    expect(ruleStanding({ ...rule(), printed: null, standing: null } as unknown as DetectionRule)).toBeNull();
    expect(ruleStanding(rule({ printed: true }))).toBeNull();
    expect(ruleStanding(rule({ printed: true, standing: "" }))).toBeNull();
  });
});
