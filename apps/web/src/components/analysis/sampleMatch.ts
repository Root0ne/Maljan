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
 * same thing. `ruleStanding` is the report's §8.2 line beside the rule's name:
 * its Precision line, or why the analyst report does not print it.
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

/** What the analyst report says of a draft beside its name (§8.2): the
 *  Precision line of a rule it prints, or why it does not print it. */
export interface RuleStanding {
  printed: boolean;
  sentence: string;
}

// The report's own wording (`detection_signatures.analyst_print_gate` and
// `precision_line`), so the card and the analyst report say the same thing.
const NOT_PRINTED_UNCOMPILED = "it does not compile";
const NOT_PRINTED_MISSES = "it does not match the sample it was drafted from";
const NOT_PRINTED_NOT_CHECKED =
  "it was not run against the sample it was drafted from, so no match by its content is shown";
const NOT_PRINTED_STORED_BEFORE =
  "it was drafted before drafts were run against their sample, so no match by its content is shown";

function notRetroHunted(what: string): string {
  return `not run against any other ${what} (no retro-hunt), so how often it fires elsewhere is not measured`;
}

/** Why the analyst report does not print the rule's body, or `null` when it does. */
function notPrintedBecause(rule: DetectionRule): string | null {
  if (rule.compile_error) return NOT_PRINTED_UNCOMPILED;
  if (rule.matches_sample === false) return NOT_PRINTED_MISSES;
  if (Array.isArray(rule.matched_by)) {
    if (rule.matched_by.includes("strings")) return null;
    const clauses = rule.matched_by.filter((part) => part !== "strings").join(" and ");
    return `it matches the sample by its ${clauses || "hash"} only, not by its content`;
  }
  if (rule.sample_not_checked) return NOT_PRINTED_NOT_CHECKED;
  if (rule.kind === "yara") return NOT_PRINTED_STORED_BEFORE;
  return null;
}

/** What a printed draft was measured on: a file rule's strings its sample
 *  held, published and stored apart; a behaviour or traffic rule's values. */
function precisionLine(rule: DetectionRule): string {
  if (rule.kind === "yara") {
    const strings = rule.sample_strings ?? [];
    const published = strings.filter((s) => s.identifier.startsWith("$s"));
    const stored = strings.filter((s) => !s.identifier.startsWith("$s"));
    const counts = [
      `${published.filter(wasFound).length} of ${published.length} published strings` +
        (stored.length > 0 ? "" : " found"),
    ];
    if (stored.length > 0) {
      counts.push(`${stored.filter(wasFound).length} of ${stored.length} stored values found`);
    }
    return (
      `Precision: its strings match the sample it was drafted from (${counts.join(", ")}), ` +
      `not its hash alone; ${notRetroHunted("file")}.`
    );
  }
  if (rule.kind === "sigma") {
    return `Precision: it selects on values this run publishes or a sandbox recorded; ${notRetroHunted("log")}.`;
  }
  return `Precision: it matches only the network indicators this run publishes; ${notRetroHunted("traffic")}.`;
}

/** The rule's line in the analyst report: its Precision line where the report
 *  prints its body, or why it does not, which for a rule that matched its
 *  sample by a hash alone says it did not match by its content. */
export function ruleStanding(rule: DetectionRule): RuleStanding {
  const why = notPrintedBecause(rule);
  if (why === null) return { printed: true, sentence: precisionLine(rule) };
  return { printed: false, sentence: `Not printed in the analyst report: ${why}.` };
}
