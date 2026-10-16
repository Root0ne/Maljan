import { describe, expect, it } from "vitest";

import type { DetectionRule } from "@/types/malware-report";
import { sampleMatchBadge } from "../sampleMatch";

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

describe("a drafted rule run against its own sample", () => {
  it("says the rule matched, with each string's first offset and the strings found nowhere", () => {
    const badge = sampleMatchBadge(
      rule({
        matches_sample: true,
        sample_strings: [
          { identifier: "$s0", offset: 8000 },
          { identifier: "$s1", offset: null },
          { identifier: "$s2", offset: 0 },
        ],
      }),
    );
    expect(badge).toEqual({
      label: "matches its sample",
      tone: "matches",
      detail:
        "Run against the sample it was drafted from: the rule matches it. " +
        "Found in the sample (first match of each): $s0 at 0x1f40, $s2 at 0x0. " +
        "Found nowhere in the sample: $s1.",
    });
  });

  it("says a rule that does not match its sample does not, in red", () => {
    const badge = sampleMatchBadge(
      rule({ matches_sample: false, sample_strings: [{ identifier: "$s0", offset: null }] }),
    );
    expect(badge?.label).toBe("does not match its sample");
    expect(badge?.tone).toBe("misses");
    expect(badge?.detail).toBe(
      "Run against the sample it was drafted from: the rule does not match it. " +
        "Found nowhere in the sample: $s0.",
    );
  });

  it("says a rule with no strings matched, and names no string", () => {
    const badge = sampleMatchBadge(rule({ matches_sample: true, sample_strings: [] }));
    expect(badge?.detail).toBe("Run against the sample it was drafted from: the rule matches it.");
  });

  it("says why a rule was not run", () => {
    const badge = sampleMatchBadge(
      rule({ sample_not_checked: "the sample could not be read (No such file or directory)" }),
    );
    expect(badge).toEqual({
      label: "not run on its sample",
      tone: "unchecked",
      detail:
        "Not run against the sample it was drafted from: " +
        "the sample could not be read (No such file or directory).",
    });
  });

  it("draws nothing for a rule stored before the check, or a draft no engine runs on a file", () => {
    expect(sampleMatchBadge(rule())).toBeNull();
    expect(sampleMatchBadge(rule({ kind: "sigma" }))).toBeNull();
    // A stored report served with explicit nulls reads the same way.
    expect(
      sampleMatchBadge({
        ...rule(),
        matches_sample: null,
        sample_strings: null,
        sample_not_checked: null,
      } as unknown as DetectionRule),
    ).toBeNull();
  });
});
