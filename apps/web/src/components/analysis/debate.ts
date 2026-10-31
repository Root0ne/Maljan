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
  /** Everything else the platform said in the round: a sycophancy flag, a
   *  fact about a line the mediation did not list. */
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
    // The mark that closes the line is the last one in it: a reason or a
    // point may quote the other mark's words earlier on.
    let best: { at: number; mark: string; kind: LineStanding } | null = null;
    for (const [mark, kind] of STANDING_MARKS) {
      for (let at = rest.lastIndexOf(mark); at >= 0; at = at > 0 ? rest.lastIndexOf(mark, at - 1) : -1) {
        const after = rest.slice(at + mark.length, -1);
        if (after !== "" && !after.startsWith(":")) continue;
        if (!best || at > best.at) best = { at, mark, kind };
        break;
      }
    }
    if (best) {
      standing = best.kind;
      reason = rest.slice(best.at + best.mark.length, -1).replace(/^:\s*/, "").trim();
      rest = rest.slice(0, best.at).trim();
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

/**
 * What the platform told the mediator, by the line each fact quotes whole,
 * and every other thing it said in the round (`unplaced`): a fact quoting no
 * listed line, a notice. Nothing said is dropped.
 */
export function factsByLine(
  rows: readonly string[],
  lines: readonly ContestedLine[],
): { byLine: Map<string, string>; unplaced: string[] } {
  const byLine = new Map<string, string>();
  const unplaced: string[] = [];
  for (const row of rows) {
    if (!row.trim()) continue;
    if (!row.startsWith(FACT_HEAD)) {
      unplaced.push(row);
      continue;
    }
    for (const fact of row.split(/\n(?=For the line ")/)) {
      // The longest line the fact opens with is the one it quotes.
      let best: ContestedLine | null = null;
      for (const line of lines) {
        if (fact.startsWith(`${FACT_HEAD}${line.raw}": `) && (!best || line.raw.length > best.raw.length)) best = line;
      }
      if (!best) {
        unplaced.push(fact);
        continue;
      }
      const said = fact.slice(FACT_HEAD.length + best.raw.length + 3).trim();
      byLine.set(best.raw, byLine.has(best.raw) ? `${byLine.get(best.raw)}\n${said}` : said);
    }
  }
  return { byLine, unplaced };
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
  // A row of any other shape (a null a stored list may hold) is skipped, never thrown on.
  const rows = (Array.isArray(transcript) ? transcript : []).filter(
    (r): r is TranscriptRow => typeof r === "object" && r !== null,
  );
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
      lines: split.lines.map((line) => ({ ...line, facts: facts.byLine.get(line.raw) ?? "" })),
      noneListed: split.noneListed,
      confidence: split.confidence ?? asFraction(entry.confidence),
      answers: inRound.filter((r) => r.role === "reviser").map(answerOf),
      notices: facts.unplaced,
    };
  });
}

/** A round in short: its lines by standing, each standing counted apart, and its answers. */
export function roundGist(round: DebateRound): string {
  const count = (standing: LineStanding) => round.lines.filter((l) => l.standing === standing).length;
  const blocking = count("blocking");
  const other = count("not-blocking");
  const unread = count("unmarked");
  const parts: string[] = [];
  if (round.lines.length === 0) parts.push(round.noneListed ? "no contradiction listed" : "no lines listed");
  else {
    if (blocking) parts.push(`${blocking} blocking`);
    if (other) parts.push(`${other} not blocking`);
    if (unread) parts.push(`${unread} mark not read`);
  }
  parts.push(`${round.answers.length} answer${round.answers.length === 1 ? "" : "s"}`);
  return parts.join(", ");
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

/** A list the summary closes with: open questions, disputes, findings. */
export interface ReportList {
  /** The heading as the summary writes it, without its colon. */
  title: string;
  items: string[];
}

export interface ParsedAgentReport {
  /** "STATIC ANALYST": who the report says wrote it; empty when it says nothing. */
  author: string;
  round: number | null;
  domain: string;
  meanConfidence: number | null;
  claims: ReportClaim[];
  /** The lists after the claims, in order. */
  lists: ReportList[];
  /** The summary's own notes after the claims (`[CONVERGENCE SIGNAL: ...]`), their brackets dropped. */
  signals: string[];
  /** What the analyst wrote besides its claims (or the whole report when it
   *  is in no known shape): its own prose. */
  prose: string;
}

const REPORT_HEAD = /^\[(.+?)\s+[—-]\s+round\s+(\d+)\]\s*$/;
const DOMAIN_LINE = /^Domain:\s*(.*?)\s*\|\s*Mean confidence:\s*(\d+(?:\.\d+)?)\s*$/;
const CLAIM_LINE = /^ {2}Claim\s+(\d+)(?:\s*\(([^)]*)\))?:\s?(.*)$/;
/** A list heading of the summary (`  Disputes:`, `  Open questions (unknowns, not absences):`). */
const LIST_HEAD = /^ {2}(\S[^\n]*?):\s*$/;
/** A note of the summary (`  [CONVERGENCE SIGNAL: no remaining disputes]`). */
const SIGNAL_LINE = /^ {2}\[([A-Z][A-Z ]*SIGNAL[^\]]*)\]\s*$/;
const LIST_ITEM = /^ {4}- ?(.*)$/;
/** The line the pipeline puts before what an analyst wrote besides its
 *  claims (`base_agent.WRITTEN_BESIDES_CLAIMS`). */
const WRITTEN_BESIDES_CLAIMS = "Written in this answer besides its claims:";

/** One claim from its first line's match and every line that continues it. */
function claimOf(match: RegExpExecArray, more: readonly string[]): ReportClaim {
  let body = [match[3], ...more].join("\n").replace(/\s+$/, "");
  let confidence: number | null = null;
  const conf = /\s\|\s*Confidence:\s*(\d+(?:\.\d+)?)$/.exec(body);
  if (conf) {
    confidence = asFraction(Number(conf[1]));
    body = body.slice(0, conf.index);
  }
  let evidence = "";
  const ev = body.lastIndexOf(" | Evidence: ");
  if (ev >= 0) {
    evidence = body.slice(ev + " | Evidence: ".length).trim();
    body = body.slice(0, ev);
  }
  return { number: match[1], topic: (match[2] ?? "").trim(), text: body.trim(), evidence, confidence };
}

/**
 * An analyst's report read into its parts, in the shape the pipeline writes
 * it (`AgentISR.to_text_summary`, then `base_agent.answer_in_force_text`): a
 * head (`[STATIC ANALYST — round 2]`, `Domain: static | Mean confidence:
 * 0.73`); one claim per `  Claim N: <text> | Evidence: <refs> | Confidence:
 * 0.95`, whose text may run on over unindented lines until the next claim;
 * the lists the summary closes with (`  Open questions (...):`,
 * `  Disputes:`, `  Findings:`, each item `    - <text>`) and its signals;
 * then, under `Written in this answer besides its claims:`, the analyst's own
 * prose. A report stored before that line existed starts its prose after a
 * blank line that closes the lists. A report without the head is all prose.
 */
export function parseAgentReport(report: string): ParsedAgentReport {
  const lines = report.replace(/\r\n/g, "\n").split("\n");
  const out: ParsedAgentReport = {
    author: "",
    round: null,
    domain: "",
    meanConfidence: null,
    claims: [],
    lists: [],
    signals: [],
    prose: "",
  };
  const head = REPORT_HEAD.exec(lines[0] ?? "");
  if (!head) {
    out.prose = report.trim();
    return out;
  }
  out.author = head[1].trim();
  out.round = Number(head[2]);
  let i = 1;
  const domain = DOMAIN_LINE.exec(lines[i] ?? "");
  if (domain) {
    out.domain = domain[1];
    out.meanConfidence = asFraction(Number(domain[2]));
    i += 1;
  }

  let claim: { match: RegExpExecArray; more: string[] } | null = null;
  let list: ReportList | null = null;
  const closeClaim = () => {
    if (claim) out.claims.push(claimOf(claim.match, claim.more));
    claim = null;
  };
  for (; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === WRITTEN_BESIDES_CLAIMS) {
      i += 1;
      break;
    }
    const opened = CLAIM_LINE.exec(line);
    if (opened && !list) {
      closeClaim();
      claim = { match: opened, more: [] };
      continue;
    }
    const signal = SIGNAL_LINE.exec(line);
    if (signal) {
      closeClaim();
      list = null;
      out.signals.push(signal[1].trim());
      continue;
    }
    const heading = LIST_HEAD.exec(line);
    if (heading && !LIST_ITEM.test(line)) {
      closeClaim();
      list = { title: heading[1].trim(), items: [] };
      out.lists.push(list);
      continue;
    }
    const item = LIST_ITEM.exec(line);
    if (list && item) {
      list.items.push(item[1]);
      continue;
    }
    // A report stored before the prose had its heading line closes its lists
    // with a blank line and goes on unindented: the prose begins there.
    if (list && line.trim() === "") {
      const next = lines.slice(i + 1).find((l) => l.trim() !== "");
      if (next !== undefined && !/^\s/.test(next)) {
        i += 1;
        break;
      }
    }
    // Any other line runs on: the item it follows, else the claim.
    if (list) {
      if (list.items.length > 0) list.items[list.items.length - 1] += `\n${line}`;
      else list.items.push(line);
      continue;
    }
    if (claim) {
      (claim as { more: string[] }).more.push(line);
      continue;
    }
    // A line after the head that belongs to no claim: the prose begins.
    break;
  }
  closeClaim();
  for (const l of out.lists) l.items = l.items.map((t) => t.replace(/\s+$/, "")).filter((t) => t.trim() !== "");
  out.prose = lines.slice(i).join("\n").trim();
  return out;
}
