/**
 * What checking a drafted YARA rule against the sample it was drafted from
 * found, as the badge DETECTION's rule card draws.
 *
 * The record is the report's (`reporting.detection_signatures`): whether the
 * rule matched, which clauses of its condition held (`matched_by`, the
 * engine's answer), each of its strings with the first offset the engine
 * matched it at or none, or why the rule was not checked. Nothing here
 * re-derives the draft's threshold: the clauses are read as recorded. The
 * sentence is the report's own §10.2 line, so the card and the report say the
 * same thing.
 */

import type { DetectionRule, RuleClause, SampleString } from "@/types/malware-report";

/** `strings`: its strings match; `hash`: it matches by a hash clause only;
 *  `misses`: no clause held; `neutral`: not checked, or a record that does not
 *  say which clause held. */
export type SampleMatchTone = "strings" | "hash" | "misses" | "neutral";

export interface SampleMatchBadge {
  label: string;
  tone: SampleMatchTone;
  /** The whole sentence: which clauses held, the strings found and those
   *  found nowhere, or the reason the rule was not checked. */
  detail: string;
}

type FoundString = SampleString & { offset: number };

function wasFound(s: SampleString): s is FoundString {
  return typeof s.offset === "number";
}

interface Held {
  sentence: string;
  label: string;
  tone: SampleMatchTone;
}

/** Which clauses held, as the report says it (`_held_by_clauses`). */
function heldByClauses(
  matches: boolean,
  matchedBy: RuleClause[] | undefined,
  found: number,
  declared: number,
): Held {
  const counted = `${found} of ${declared} strings found`;
  if (!Array.isArray(matchedBy)) {
    return matches
      ? { sentence: "the rule matches it.", label: "matches its sample", tone: "neutral" }
      : {
          sentence: "the rule does not match it.",
          label: "does not match its sample",
          tone: "misses",
        };
  }
  const hashes = matchedBy.filter((part) => part !== "strings");
  const named = hashes.join(" and ");
  if (matchedBy.includes("strings")) {
    const also = hashes.length > 0 ? `, and so ${hashes.length > 1 ? "do" : "does"} its ${named}` : "";
    return {
      sentence: `its strings match it (${counted})${also}.`,
      label: "its strings match its sample",
      tone: "strings",
    };
  }
  if (hashes.length > 0) {
    const rest = declared > 0 ? `its strings do not (${counted}).` : "the draft declares no strings.";
    return {
      sentence: `the rule matches it by its ${named} only; ${rest}`,
      label: "matches its sample by hash only",
      tone: "hash",
    };
  }
  return {
    sentence: `the rule does not match it${declared > 0 ? ` (${counted})` : ""}.`,
    label: "does not match its sample",
    tone: "misses",
  };
}

/** The badge for a rule's check against its own sample; `null` for a rule that
 *  carries none — a Sigma or Suricata draft, or a rule stored before the check. */
export function sampleMatchBadge(rule: DetectionRule): SampleMatchBadge | null {
  if (rule.sample_not_checked) {
    const why = rule.sample_not_checked.replace(/\.+$/, "");
    return {
      label: "not run on its sample",
      tone: "neutral",
      detail: `Not run against the sample it was drafted from: ${why}.`,
    };
  }
  if (typeof rule.matches_sample !== "boolean") return null;
  const strings = rule.sample_strings ?? [];
  const found = strings.filter(wasFound);
  const nowhere = strings.filter((s) => !wasFound(s));
  const held = heldByClauses(rule.matches_sample, rule.matched_by, found.length, strings.length);
  const said = [`Run against the sample it was drafted from: ${held.sentence}`];
  if (found.length > 0) {
    const where = found.map((s) => `${s.identifier} at 0x${s.offset.toString(16)}`);
    said.push(`Found in the sample (first match of each): ${where.join(", ")}.`);
  }
  if (nowhere.length > 0) {
    said.push(`Found nowhere in the sample: ${nowhere.map((s) => s.identifier).join(", ")}.`);
  }
  return { label: held.label, tone: held.tone, detail: said.join(" ") };
}
