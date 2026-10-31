/**
 * The debate read off the stored records: a mediation's words, its listed
 * lines with who must revise and whether each blocks, what the ledger states
 * for each, the revisions that answered the round, the outcome, and an
 * analyst's report read into claims and prose. The shapes are a stored run's
 * (benchmark haiku7), cut down.
 */

import { describe, expect, it } from "vitest";

import type { TranscriptRow } from "@/lib/conversation";
import {
  analystKey,
  asFraction,
  debateOutcome,
  debateRounds,
  factsByLine,
  hasDebate,
  parseAgentReport,
  parseLine,
  splitMediation,
} from "../debate";

const LINE_1 =
  "[analysts: STATIC ANALYST, ALL_TOOLS_QU1CKSC0PE ANALYST] STATIC ANALYST claim 21 says routine 0x463c opens another process; " +
  "ALL_TOOLS_REVERSER_GHIDRA claim 31 says it opens its own PID (ev_0068). [blocking: target process of OpenProcess in 0x463c is stated in incompatible ways]";
const LINE_2 =
  "[analysts: NETWORK ANALYST] [carried: L5] Claim 42 rejects the 12-GET count; ev_0089 lists 12 GET requests. " +
  "[not blocking: the list is an incomplete summary]";

const ARGUMENT = `The analysts agree on the core facts.\n\nContradictions: ${LINE_1}; ${LINE_2}\nConfidence: 0.55`;

const TRANSCRIPT: TranscriptRow[] = [
  { seq: 1, speaker: "static", role: "analyst", round: 0, status: "complete", text: "37 claims" },
  { seq: 2, speaker: "pipeline", role: "negotiator", round: 1, status: "complete", text: "Mediator: ..." },
  {
    seq: 3,
    speaker: "pipeline",
    role: "system",
    round: 1,
    status: "complete",
    text: `For the line "${LINE_1}": 0x463c is listed in ev_0068.\nFor the line "${LINE_2}": 0x5030 is listed in ev_0064.`,
  },
  {
    seq: 4,
    speaker: "Sycophancy detector",
    role: "system",
    round: 1,
    status: "complete",
    text: "Agents converged without new evidence.",
  },
  {
    seq: 5,
    speaker: "static",
    role: "reviser",
    round: 1,
    status: "complete",
    text: "35 evidence-backed claims.",
    confidence: 0.7,
    dissent: ["Reverser claim 27 rests on ev_0096, which I cannot read."],
    report: "[STATIC ANALYST — round 1]\nDomain: static | Mean confidence: 0.73\n  Claim 1: A DLL. | Evidence: ev_0001 | Confidence: 0.95",
  },
  { seq: 6, speaker: "network", role: "reviser", round: 2, status: "complete", text: "later round" },
];

const LOG = {
  is_consensus: false,
  iteration_count: 2,
  mediation_failed: false,
  confidence_history: [0.7235, 0.7139],
  consensus_applicable: true,
  sycophancy_detected: false,
  discussion_history: [
    { round: 1, agent: "Mediator", status: "complete", note: "", confidence: 55.00000000000001, argument: ARGUMENT },
    { round: 2, agent: "Mediator", status: "timeout", note: "The mediation timed out.", confidence: null, argument: "timed out" },
  ],
};

describe("a contested line", () => {
  it("reads who must revise, the mediator's markers, the point and its standing", () => {
    const line = parseLine(LINE_2);
    expect(line.analysts).toEqual(["NETWORK ANALYST"]);
    expect(line.markers).toEqual(["carried: L5"]);
    expect(line.text).toBe("Claim 42 rejects the 12-GET count; ev_0089 lists 12 GET requests.");
    expect(line.standing).toBe("not-blocking");
    expect(line.reason).toBe("the list is an incomplete summary");
  });

  it("keeps a line with no fields whole, unmarked", () => {
    const line = parseLine("Something the mediator wrote another way.");
    expect(line).toMatchObject({ analysts: [], standing: "unmarked", text: "Something the mediator wrote another way." });
  });

  it("maps the written name to the roster key", () => {
    expect(analystKey("ALL_TOOLS_QU1CKSC0PE ANALYST")).toBe("all_tools_qu1cksc0pe");
    expect(analystKey("STATIC ANALYST")).toBe("static");
  });
});

describe("a mediation", () => {
  it("splits its words, its lines (a semicolon inside a line kept) and its confidence", () => {
    const split = splitMediation(ARGUMENT);
    expect(split.words).toBe("The analysts agree on the core facts.");
    expect(split.lines.map((l) => l.raw)).toEqual([LINE_1, LINE_2]);
    expect(split.lines[0].standing).toBe("blocking");
    expect(split.confidence).toBeCloseTo(0.55);
  });

  it("says when no contradiction was listed", () => {
    expect(splitMediation("All agree.\n\nContradictions: None\nConfidence: 0.90")).toMatchObject({
      words: "All agree.",
      lines: [],
      noneListed: true,
    });
  });

  it("keeps an answer of any other shape as words", () => {
    expect(splitMediation("timed out")).toEqual({ words: "timed out", lines: [], noneListed: false, confidence: null });
    const odd = "Words.\n\nContradictions: free prose, no fields\nConfidence: 0.5";
    expect(splitMediation(odd).words).toBe(odd);
    expect(splitMediation(odd).lines).toEqual([]);
  });

  it("puts each ledger fact under the line it quotes whole", () => {
    const lines = splitMediation(ARGUMENT).lines;
    const facts = factsByLine([TRANSCRIPT[2].text], lines);
    expect(facts.get(LINE_1)).toBe("0x463c is listed in ev_0068.");
    expect(facts.get(LINE_2)).toBe("0x5030 is listed in ev_0064.");
  });
});

describe("the rounds", () => {
  const rounds = debateRounds(LOG, TRANSCRIPT);

  it("draws one round per mediation, with its lines, facts, answers and notices", () => {
    expect(rounds).toHaveLength(2);
    const [first] = rounds;
    expect(first.round).toBe(1);
    expect(first.confidence).toBeCloseTo(0.55);
    expect(first.lines[0].facts).toBe("0x463c is listed in ev_0068.");
    expect(first.answers).toHaveLength(1);
    expect(first.answers[0]).toMatchObject({ speaker: "static", confidence: 0.7 });
    expect(first.answers[0].dissent).toEqual(["Reverser claim 27 rests on ev_0096, which I cannot read."]);
    expect(first.notices).toEqual(["Agents converged without new evidence."]);
  });

  it("keeps a failed round's status, note and words, and reads the stored percentage as a fraction", () => {
    const second = rounds[1];
    expect(second).toMatchObject({ status: "timeout", note: "The mediation timed out.", words: "timed out", lines: [] });
    expect(second.answers.map((a) => a.speaker)).toEqual(["network"]);
    expect(asFraction(55.00000000000001)).toBeCloseTo(0.55);
    expect(asFraction(0.4)).toBe(0.4);
  });

  it("has no rounds without a log", () => {
    expect(debateRounds(null, TRANSCRIPT)).toEqual([]);
    expect(debateRounds({ discussion_history: "x" }, [])).toEqual([]);
  });
});

describe("the outcome", () => {
  it("says how the debate ended and keeps the figures", () => {
    const outcome = debateOutcome(
      {
        final_confidence: 0.7378,
        rounds_completed: 4,
        sycophancy_events: 0,
        confidence_history: [0.72, 0.71, 0.74, 0.74],
        termination_reason: "convergence",
      },
      LOG,
    );
    expect(outcome.ending).toMatch(/stopped moving/);
    expect(outcome).toMatchObject({ rounds: 4, consensus: false, sycophancy: 0, mediationFailed: false, other: {} });
    expect(outcome.confidenceHistory).toEqual([0.72, 0.71, 0.74, 0.74]);
    expect(outcome.finalConfidence).toBeCloseTo(0.7378);
  });

  it("states no consensus where none applied, and keeps fields it does not read", () => {
    const outcome = debateOutcome({ termination_reason: "not_applicable", extra: 1 }, { is_consensus: null, consensus_applicable: false });
    expect(outcome.consensus).toBeNull();
    expect(outcome.ending).toMatch(/No agreement was measured/);
    expect(outcome.other).toEqual({ extra: 1 });
  });

  it("names a reason it has no sentence for, and says nothing for none", () => {
    expect(debateOutcome({ termination_reason: "brand_new" }, null).ending).toBe("The debate ended (brand new)");
    expect(debateOutcome({}, null).ending).toBe("");
  });

  it("knows whether any debate was recorded", () => {
    expect(hasDebate(null, null)).toBe(false);
    expect(hasDebate({}, { discussion_history: [] })).toBe(false);
    expect(hasDebate(null, LOG)).toBe(true);
  });
});

describe("an analyst's report", () => {
  const REPORT = [
    "[ALL_TOOLS_STATIC_R2 ANALYST — round 2]",
    "Domain: static | Mean confidence: 0.72",
    "  Claim 1: The file decodes `init -zzzz=\"%s\\%s\"` at run time. | Evidence: [ev_0019] 81 strings; [ev_0021] 101 | Confidence: 0.85",
    "  Claim 2 (identity): An x64 DLL. | Evidence: ev_0004 (dll) | Confidence: 0.95",
    "",
    "- **My round-1 claim 18: revised.** Cross-process access is not established.",
  ].join("\n");

  it("reads the head, each claim with its evidence and confidence, and the prose after", () => {
    const parsed = parseAgentReport(REPORT);
    expect(parsed).toMatchObject({ author: "ALL_TOOLS_STATIC_R2 ANALYST", round: 2, domain: "static", meanConfidence: 0.72 });
    expect(parsed.claims).toHaveLength(2);
    expect(parsed.claims[0]).toEqual({
      number: "1",
      topic: "",
      text: 'The file decodes `init -zzzz="%s\\%s"` at run time.',
      evidence: "[ev_0019] 81 strings; [ev_0021] 101",
      confidence: 0.85,
    });
    expect(parsed.claims[1]).toMatchObject({ number: "2", topic: "identity", evidence: "ev_0004 (dll)" });
    expect(parsed.prose).toBe("- **My round-1 claim 18: revised.** Cross-process access is not established.");
  });

  it("reads a report of any other shape as prose", () => {
    const parsed = parseAgentReport("[ERROR] dynamic: sandbox unreachable");
    expect(parsed.claims).toEqual([]);
    expect(parsed.author).toBe("");
    expect(parsed.prose).toBe("[ERROR] dynamic: sandbox unreachable");
  });
});
