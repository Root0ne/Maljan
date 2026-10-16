/**
 * What running a drafted YARA rule against the sample it was drafted from
 * found, as the badge DETECTION's rule card draws.
 *
 * The record is the report's (`reporting.detection_signatures`): whether the
 * rule matched, each of its strings with the first offset the engine matched
 * it at or none, or why the rule was not run. The sentence is the report's
 * own §10.2 line, so the card and the report say the same thing.
 */

import type { DetectionRule, SampleString } from "@/types/malware-report";

type FoundString = SampleString & { offset: number };

function wasFound(s: SampleString): s is FoundString {
  return typeof s.offset === "number";
}

export type SampleMatchTone = "matches" | "misses" | "unchecked";

export interface SampleMatchBadge {
  label: string;
  tone: SampleMatchTone;
  /** The whole sentence: the strings found, those found nowhere, or the reason. */
  detail: string;
}

/** The badge for a rule's run against its own sample; `null` for a rule that
 *  carries none — a Sigma or Suricata draft, or a rule stored before the check. */
export function sampleMatchBadge(rule: DetectionRule): SampleMatchBadge | null {
  if (rule.sample_not_checked) {
    const why = rule.sample_not_checked.replace(/\.+$/, "");
    return {
      label: "not run on its sample",
      tone: "unchecked",
      detail: `Not run against the sample it was drafted from: ${why}.`,
    };
  }
  if (typeof rule.matches_sample !== "boolean") return null;
  const strings = rule.sample_strings ?? [];
  const found = strings.filter(wasFound);
  const nowhere = strings.filter((s) => !wasFound(s));
  const said = [
    `Run against the sample it was drafted from: the rule ${
      rule.matches_sample ? "matches it." : "does not match it."
    }`,
  ];
  if (found.length > 0) {
    const where = found.map((s) => `${s.identifier} at 0x${s.offset.toString(16)}`);
    said.push(`Found in the sample (first match of each): ${where.join(", ")}.`);
  }
  if (nowhere.length > 0) {
    said.push(`Found nowhere in the sample: ${nowhere.map((s) => s.identifier).join(", ")}.`);
  }
  return {
    label: rule.matches_sample ? "matches its sample" : "does not match its sample",
    tone: rule.matches_sample ? "matches" : "misses",
    detail: said.join(" "),
  };
}
