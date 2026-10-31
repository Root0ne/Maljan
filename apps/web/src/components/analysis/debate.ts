/**
 * The analysts' debate, read for the Debate view under Evidence.
 *
 * Three stored records describe one debate. The negotiation log
 * (`report.negotiation_log`) keeps each mediation round: the mediator's own
 * words, then the lines it listed after `Contradictions: `, each opening with
 * `[analysts: <name>, ...]` (who must revise over it) and closing with a
 * `[blocking: <reason>]` or `[not blocking: <reason>]` mark, then
 * `Confidence: <n>` (`JudgeAgent._mediate_round`). The recorded conversation
 * (`report.transcript`) keeps what the platform told the mediator about each
 * line (`For the line "<line>": <what the ledger states>`) and every
 * analyst's revision that answered the round. The structured report's
 * `negotiation_summary` keeps how the debate ended.
 *
 * Everything here is read off those records; nothing is inferred. A
 * mediation written in a shape this reader does not know keeps its words
 * whole and lists no lines, so nothing it said is lost.
 */

import type { TranscriptRow } from "@/lib/conversation";

export type LineStanding = "blocking" | "not-blocking" | "unmarked";

export interface ContestedLine {
  /** The line exactly as the mediator listed it: the key its facts quote. */
  raw: string;
  /** The analysts the mediator names, as written ("STATIC ANALYST"). */
  analysts: string[];
  /** `carried: L4`, `new`: the mediator's own markers, as written. */
  markers: string[];
  /** The contested point, without its fields. */
  text: string;
  standing: LineStanding;
  /** Why the mediator marked it so; empty when it gave no reason. */
  reason: string;
  /** What the evidence ledger states for this line, as the platform put it
   *  to the mediator; empty when nothing was put. */
  facts: string;
}

export interface DebateAnswer {
  speaker: string;
  /** The operator's label for the speaker when the line went out. */
  displayName: string | null;
  status: string;
  text: string;
  confidence: number | null;
  /** The points the analyst disputed in this answer. */
  dissent: string[];
  report: string | null;
  reportTruncated: boolean;
}

export interface DebateRound {
  round: number;
  /** Who mediated: "Mediator" on every stored run. */
  agent: string;
  /** `complete`, `failed` or `timeout`. */
  status: string;
  /** The platform's sentence about the round, apart from the mediator's. */
  note: string;
  /** The mediator's words before its listed lines (all of them when the
   *  lines could not be read apart). */
  words: string;
  lines: ContestedLine[];
  /** True when the mediation said no contradiction stands. */
  noneListed: boolean;
  /** The mediator's stated confidence for the round, 0 to 1. */
  confidence: number | null;
  /** The revisions that answered this round, in the order they were said. */
  answers: DebateAnswer[];
  /** Other things the platform said in the round (a sycophancy flag). */
  notices: string[];
}

export interface DebateOutcome {
  rounds: number | null;
  /** How the debate ended, as a sentence; empty when nothing says. */
  ending: string;
  /** The raw termination reason, for the reader who wants the code word. */
  reason: string;
  /** Mean claim confidence per round, 0 to 1. */
  confidenceHistory: number[];
  finalConfidence: number | null;
  /** `true` / `false` when measured; `null` when it did not apply or is not stated. */
  consensus: boolean | null;
  /** Rounds flagged as agreement without new evidence. */
  sycophancy: number | null;
  mediationFailed: boolean;
  /** Fields of the summary this reader does not interpret, kept whole. */
  other: Record<string, unknown>;
}

const LINES_HEAD = "\n\nContradictions: ";
const CONFIDENCE_TAIL = /\nConfidence: (\d+(?:\.\d+)?)\s*$/;
const ANALYSTS_FIELD = /^\[analysts:\s*([^\]]*)\]\s*/;
const MARKER_FIELD = /^\[(carried:[^\]]*|new)\]\s*/;
const FACT_HEAD = 'For the line "';

/** The standing marks a line can close with, longest first. */
const STANDING_MARKS: readonly [string, LineStanding][] = [
  ["[not blocking", "not-blocking"],
  ["[blocking", "blocking"],
];

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function finite(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** A confidence as a fraction: the log stores the mediator's as a percentage. */
export function asFraction(value: unknown): number | null {
  const n = finite(value);
  if (n === null) return null;
  return n > 1 ? Math.min(n / 100, 1) : Math.max(n, 0);
}

function strings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((item) => (typeof item === "string" ? item : item == null ? "" : JSON.stringify(item)))
    .filter((item) => item.trim() !== "");
}

/**
 * One listed line read into its fields. A line with no `[analysts: ...]`
 * opening is kept whole as its text, unmarked.
 */
export function parseLine(raw: string): ContestedLine {
  let rest = raw.trim();
  const analysts: string[] = [];
  const markers: string[] = [];
  const named = ANALYSTS_FIELD.exec(rest);
  if (named) {
    analysts.push(...named[1].split(",").map((a) => a.trim()).filter(Boolean));
    rest = rest.slice(named[0].length);
    for (let marker = MARKER_FIELD.exec(rest); marker; marker = MARKER_FIELD.exec(rest)) {
      markers.push(marker[1].trim());
      rest = rest.slice(marker[0].length);
    }
  }
  let standing: LineStanding = "unmarked";
  let reason = "";
  if (rest.endsWith("]")) {
    for (const [mark, kind] of STANDING_MARKS) {
      const at = rest.lastIndexOf(mark);
      if (at < 0) continue;
      const after = rest.slice(at + mark.length, -1);
      if (after !== "" && !after.startsWith(":")) continue;
      standing = kind;
      reason = after.replace(/^:\s*/, "").trim();
      rest = rest.slice(0, at).trim();
      break;
    }
  }
  return { raw, analysts, markers, text: rest, standing, reason, facts: "" };
}

/**
 * A mediation's finding read apart: its own words, its listed lines and its
 * stated confidence. A finding without the `Contradictions:` tail (an error,
 * a mediation that did not apply) is all words.
 */
export function splitMediation(argument: string): {
  words: string;
  lines: ContestedLine[];
  noneListed: boolean;
  confidence: number | null;
} {
  const at = argument.lastIndexOf(LINES_HEAD);
  if (at < 0) return { words: argument.trim(), lines: [], noneListed: false, confidence: null };
  const tail = argument.slice(at + LINES_HEAD.length);
  const stated = CONFIDENCE_TAIL.exec(tail);
  const joined = (stated ? tail.slice(0, stated.index) : tail).trim();
  const confidence = stated ? asFraction(Number(stated[1])) : null;
  const words = argument.slice(0, at).trim();
  if (joined === "None" || joined === "") return { words, lines: [], noneListed: joined === "None", confidence };
  // Every line opens with its analysts field, so a line ends where the next
  // field opens. A tail that does not open with one is not split.
  if (!joined.startsWith("[analysts:")) return { words: argument.trim(), lines: [], noneListed: false, confidence };
  const lines = joined.split(/; (?=\[analysts:)/).map(parseLine);
  return { words, lines, noneListed: false, confidence };
}

/** What the platform told the mediator, by the line each fact quotes whole. */
export function factsByLine(rows: readonly string[], lines: readonly ContestedLine[]): Map<string, string> {
  const out = new Map<string, string>();
  const facts = rows.flatMap((row) => row.split(/\n(?=For the line ")/));
  for (const fact of facts) {
    if (!fact.startsWith(FACT_HEAD)) continue;
    // The longest line the fact opens with is the one it quotes.
    let best: ContestedLine | null = null;
    for (const line of lines) {
      if (fact.startsWith(`${FACT_HEAD}${line.raw}": `) && (!best || line.raw.length > best.raw.length)) best = line;
    }
    if (!best) continue;
    const said = fact.slice(FACT_HEAD.length + best.raw.length + 3).trim();
    out.set(best.raw, out.has(best.raw) ? `${out.get(best.raw)}\n${said}` : said);
  }
  return out;
}

/** The roster key an analyst named in a line goes by: "ALL_TOOLS_DISASSEMBLER ANALYST" is `all_tools_disassembler`. */
export function analystKey(named: string): string {
  return named
    .trim()
    .replace(/\s+analyst$/i, "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_");
}

function answerOf(row: TranscriptRow): DebateAnswer {
  return {
    speaker: row.speaker,
    displayName: row.display_name ?? null,
    status: row.status,
    text: text(row.text),
    confidence: asFraction(row.confidence),
    dissent: strings(row.dissent),
    report: text(row.report) || null,
    reportTruncated: Boolean(row.report_truncated),
  };
}

/** Whether a negotiation log entry is a mediation (its `agent`). */
function isMediation(entry: Record<string, unknown>): boolean {
  return /mediator/i.test(text(entry.agent)) || text(entry.argument).includes(LINES_HEAD);
}

/**
 * The debate's rounds: one per mediation the log kept, each with its lines,
 * what the ledger states for them, and the revisions that answered it.
 */
export function debateRounds(
  log: Record<string, unknown> | null | undefined,
  transcript: readonly TranscriptRow[] | null | undefined,
): DebateRound[] {
  const history = Array.isArray(log?.discussion_history) ? (log.discussion_history as unknown[]) : [];
  const rows = transcript ?? [];
  const mediations = history.filter(
    (e): e is Record<string, unknown> => typeof e === "object" && e !== null && isMediation(e as Record<string, unknown>),
  );
  return mediations.map((entry, i) => {
    const round = finite(entry.round) ?? i + 1;
    const split = splitMediation(text(entry.argument));
    const inRound = rows.filter((r) => r.round === round);
    const said = inRound.filter((r) => r.role === "system").map((r) => text(r.text));
    const facts = factsByLine(said, split.lines);
    return {
      round,
      agent: text(entry.agent) || "Mediator",
      status: text(entry.status) || "complete",
      note: text(entry.note).trim(),
      words: split.words,
      lines: split.lines.map((line) => ({ ...line, facts: facts.get(line.raw) ?? "" })),
      noneListed: split.noneListed,
      confidence: split.confidence ?? asFraction(entry.confidence),
      answers: inRound.filter((r) => r.role === "reviser").map(answerOf),
      notices: said.filter((s) => s.trim() && !s.startsWith(FACT_HEAD)),
    };
  });
}

/** How a debate ended, by the reason the run summary records. */
const ENDINGS: Record<string, string> = {
  consensus: "The analysts reached consensus",
  convergence: "The analysts' confidence stopped moving between rounds, so the debate closed without full agreement",
  converged: "The analysts' confidence stopped moving between rounds, so the debate closed without full agreement",
  hard_limit: "The debate reached its round limit",
  mediation_failed: "A mediation round failed, so the debate did not run to its end",
  not_mediated: "The last mediator wrote no answer, so the round was not mediated",
  not_revised: "No analyst was revised in the last round, so the answers in force went to the judge",
  no_contested_point: "The last mediation listed no blocking line, so no revision round was needed",
  contested_points_unchanged: "The last revision round changed none of the contested points",
  reworded: "The last revisions only reworded the claims in force",
  ledger_stated: "Every remaining blocking line stated only counts the ledger already states",
  not_applicable: "No agreement was measured: fewer than two analysts produced claims, or the debate did not run",
};

const KNOWN_SUMMARY_KEYS = new Set([
  "rounds_completed",
  "termination_reason",
  "confidence_history",
  "final_confidence",
  "sycophancy_events",
]);

/** The debate's outcome, from the report's summary and the log beside it. */
export function debateOutcome(
  summary: Record<string, unknown> | null | undefined,
  log: Record<string, unknown> | null | undefined,
): DebateOutcome {
  const s = summary ?? {};
  const l = log ?? {};
  const reason = text(s.termination_reason).trim();
  const rounds = finite(s.rounds_completed) ?? finite(l.iteration_count);
  const history = Array.isArray(s.confidence_history)
    ? s.confidence_history
    : Array.isArray(l.confidence_history)
      ? l.confidence_history
      : [];
  const confidenceHistory = history.map(asFraction).filter((n): n is number => n !== null);
  const applicable = l.consensus_applicable !== false && reason !== "not_applicable";
  const ending = ENDINGS[reason] ?? (reason && reason !== "unknown" ? `The debate ended (${reason.replace(/_/g, " ")})` : "");
  const other: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(s)) if (!KNOWN_SUMMARY_KEYS.has(key)) other[key] = value;
  return {
    rounds,
    ending,
    reason,
    confidenceHistory,
    finalConfidence: asFraction(s.final_confidence),
    consensus: applicable && typeof l.is_consensus === "boolean" ? l.is_consensus : null,
    sycophancy: finite(s.sycophancy_events) ?? (l.sycophancy_detected === true ? 1 : null),
    mediationFailed: l.mediation_failed === true,
    other,
  };
}

/** Whether a report has any debate record at all. */
export function hasDebate(
  summary: Record<string, unknown> | null | undefined,
  log: Record<string, unknown> | null | undefined,
): boolean {
  const history = log?.discussion_history;
  return (Array.isArray(history) && history.length > 0) || Object.keys(summary ?? {}).length > 0;
}

/* ── An analyst's report ─────────────────────────────────────────────── */

export interface ReportClaim {
  number: string;
  /** The topic the claim is filed under ("identity"), when it names one. */
  topic: string;
  text: string;
  evidence: string;
  confidence: number | null;
}

export interface ParsedAgentReport {
  /** "STATIC ANALYST": who the report says wrote it; empty when it says nothing. */
  author: string;
  round: number | null;
  domain: string;
  meanConfidence: number | null;
  claims: ReportClaim[];
  /** What follows the claims (or the whole report when it has none): the
   *  analyst's own prose. */
  prose: string;
}

const REPORT_HEAD = /^\[(.+?)\s+[—-]\s+round\s+(\d+)\]\s*$/;
const DOMAIN_LINE = /^Domain:\s*(.*?)\s*\|\s*Mean confidence:\s*(\d+(?:\.\d+)?)\s*$/;
const CLAIM_LINE = /^\s+Claim\s+(\d+)(?:\s*\(([^)]*)\))?:\s?(.*)$/;

function claimOf(match: RegExpExecArray): ReportClaim {
  let body = match[3];
  let confidence: number | null = null;
  const conf = /\s\|\s*Confidence:\s*(\d+(?:\.\d+)?)\s*$/.exec(body);
  if (conf) {
    confidence = asFraction(Number(conf[1]));
    body = body.slice(0, conf.index);
  }
  let evidence = "";
  const ev = body.indexOf(" | Evidence: ");
  if (ev >= 0) {
    evidence = body.slice(ev + " | Evidence: ".length).trim();
    body = body.slice(0, ev);
  }
  return { number: match[1], topic: (match[2] ?? "").trim(), text: body.trim(), evidence, confidence };
}

/**
 * An analyst's report read into its parts. The pipeline writes a head
 * (`[STATIC ANALYST — round 2]`, `Domain: static | Mean confidence: 0.73`)
 * and one indented line per claim (`Claim 1: <text> | Evidence: <refs> |
 * Confidence: 0.95`); what follows is the analyst's own prose. A report in
 * any other shape is all prose.
 */
export function parseAgentReport(report: string): ParsedAgentReport {
  const lines = report.replace(/\r\n/g, "\n").split("\n");
  const out: ParsedAgentReport = { author: "", round: null, domain: "", meanConfidence: null, claims: [], prose: "" };
  let i = 0;
  const head = REPORT_HEAD.exec(lines[0] ?? "");
  if (head) {
    out.author = head[1].trim();
    out.round = Number(head[2]);
    i = 1;
  }
  const domain = DOMAIN_LINE.exec(lines[i] ?? "");
  if (domain) {
    out.domain = domain[1];
    out.meanConfidence = asFraction(Number(domain[2]));
    i += 1;
  }
  for (; i < lines.length; i++) {
    const claim = CLAIM_LINE.exec(lines[i]);
    if (claim) {
      out.claims.push(claimOf(claim));
      continue;
    }
    // An indented line under a claim continues it.
    if (out.claims.length > 0 && /^\s{3,}\S/.test(lines[i])) {
      out.claims[out.claims.length - 1].text += ` ${lines[i].trim()}`;
      continue;
    }
    break;
  }
  out.prose = lines.slice(i).join("\n").trim();
  return out;
}
