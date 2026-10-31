/**
 * The debate read off the stored records: a mediation's words, its listed
 * lines with who must revise and whether each blocks, what the ledger states
 * for each, the revisions that answered the round, the outcome, and an
 * analyst's report read into claims and prose. The shapes are a stored run's
 * (a stored benchmark run), cut down.
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
  roundGist,
  splitMediation,
} from "../debate";

const LINE_1 =
  "[analysts: STATIC ANALYST, ALL_TOOLS_SCANNER ANALYST] STATIC ANALYST claim 21 says routine 0x463c opens another process; " +
  "ALL_TOOLS_REVERSER claim 31 says it opens its own PID (ev_0068). [blocking: target process of OpenProcess in 0x463c is stated in incompatible ways]";
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

  it("reads the standing from the mark that closes the line, whatever the point quotes", () => {
    const quoting = parseLine(
      "[analysts: A ANALYST] The analyst wrote [blocking: x] in its answer [not blocking: the quote is not a mark]",
    );
    expect(quoting.standing).toBe("not-blocking");
    expect(quoting.reason).toBe("the quote is not a mark");
    expect(quoting.text).toBe("The analyst wrote [blocking: x] in its answer");
    const reverse = parseLine("[analysts: A ANALYST] It said [not blocking: y] before. [blocking: it blocks]");
    expect(reverse).toMatchObject({ standing: "blocking", reason: "it blocks", text: "It said [not blocking: y] before." });
    const bare = parseLine("[analysts: A ANALYST] A point. [blocking]");
    expect(bare).toMatchObject({ standing: "blocking", reason: "", text: "A point." });
  });

  it("maps the written name to the roster key", () => {
    expect(analystKey("ALL_TOOLS_SCANNER ANALYST")).toBe("all_tools_scanner");
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
    expect(facts.byLine.get(LINE_1)).toBe("0x463c is listed in ev_0068.");
    expect(facts.byLine.get(LINE_2)).toBe("0x5030 is listed in ev_0064.");
    expect(facts.unplaced).toEqual([]);
  });

  it("keeps a fact that quotes no listed line, and every other thing said, as unplaced", () => {
    const lines = splitMediation(ARGUMENT).lines;
    const stray = 'For the line "[analysts: X ANALYST] a line this round did not list [blocking: y]": 0x1 is listed in ev_0001.';
    const facts = factsByLine([`${TRANSCRIPT[2].text}\n${stray}`, "Agents converged.", "  "], lines);
    expect(facts.byLine.size).toBe(2);
    expect(facts.unplaced).toEqual([stray, "Agents converged."]);
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

  it("counts each standing apart in a round's gist, a mark not read among them", () => {
    const round = { ...rounds[0], lines: [parseLine(LINE_1), parseLine(LINE_2), parseLine("[analysts: A ANALYST] no mark")] };
    expect(roundGist(round)).toBe("1 blocking, 1 not blocking, 1 mark not read, 1 answer");
    expect(roundGist({ ...rounds[0], lines: [], noneListed: true, answers: [] })).toBe("no contradiction listed, 0 answers");
  });

  it("skips a null or odd transcript row and history entry rather than throwing", () => {
    const odd = [null, 7, ...TRANSCRIPT] as unknown as TranscriptRow[];
    const rounds = debateRounds({ ...LOG, discussion_history: [null, ...LOG.discussion_history] }, odd);
    expect(rounds).toHaveLength(2);
    expect(rounds[0].answers).toHaveLength(1);
    expect(debateRounds(LOG, "x" as unknown as TranscriptRow[])[0].answers).toEqual([]);
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
  // The shape a stored run's final report has (`AgentISR.to_text_summary`
  // and `answer_in_force_text`), cut down: a claim that runs on over
  // unindented lines, its evidence and confidence on its last line, the
  // lists after the claims, then the prose under its heading.
  const REPORT = [
    "[DYNAMIC ANALYST — round 1]",
    "Domain: dynamic | Mean confidence: 0.77",
    "  Claim 1: The file is an unsigned 64-bit DLL. | Evidence: [ev_0001] pe windows; [ev_0003] signature none | Confidence: 0.95",
    "  Claim 2: The environment gate in 0x3868 runs in this order.",
    "(a) Resolver init 0x6328 must succeed.",
    String.raw`(b) The format "%s\%s" builds C:\Users\Public\upd.exe.`,
    "",
    "(c) CreateMutexW, with exit if GetLastError == 0xb7. | Evidence: [ev_0064] 0x3868 listing | Confidence: 0.80",
    "  Claim 3 (identity): An x64 DLL. | Evidence: ev_0004 (dll) | Confidence: 0.95",
    "  Open questions (unknowns, not absences):",
    "    - What name is passed to CreateMutexW in 0x3868 | Why open: tool_failed | Detail: The call passes (0, 0).",
    "  Disputes:",
    "    - Network claim 2 tags the wait T1497.003. Disputed.",
    "The delay is literal (ev_0064).",
    "    - QU claim 24 says no RC4 use is traced. Disputed.",
    "  Findings:",
    "    - Gated init: the export loops resident only on success.",
    "Written in this answer besides its claims:",
    "# DYNAMIC ANALYST, round 1 (revised)",
    "",
    "- **Citation scope.** I re-read ev_0064.",
  ].join("\n");

  it("reads every claim whole, with its evidence and confidence, however many lines it runs on", () => {
    const parsed = parseAgentReport(REPORT);
    expect(parsed).toMatchObject({ author: "DYNAMIC ANALYST", round: 1, domain: "dynamic", meanConfidence: 0.77 });
    expect(parsed.claims.map((c) => c.number)).toEqual(["1", "2", "3"]);
    expect(parsed.claims.every((c) => c.evidence && c.confidence !== null)).toBe(true);
    expect(parsed.claims[1]).toEqual({
      number: "2",
      topic: "",
      text: [
        "The environment gate in 0x3868 runs in this order.",
        "(a) Resolver init 0x6328 must succeed.",
        String.raw`(b) The format "%s\%s" builds C:\Users\Public\upd.exe.`,
        "",
        "(c) CreateMutexW, with exit if GetLastError == 0xb7.",
      ].join("\n"),
      evidence: "[ev_0064] 0x3868 listing",
      confidence: 0.8,
    });
    expect(parsed.claims[2]).toMatchObject({ topic: "identity", evidence: "ev_0004 (dll)", confidence: 0.95 });
  });

  it("reads the lists after the claims, an item that runs on kept whole, then the prose under its heading", () => {
    const parsed = parseAgentReport(REPORT);
    expect(parsed.lists).toEqual([
      {
        title: "Open questions (unknowns, not absences)",
        items: ["What name is passed to CreateMutexW in 0x3868 | Why open: tool_failed | Detail: The call passes (0, 0)."],
      },
      {
        title: "Disputes",
        items: [
          "Network claim 2 tags the wait T1497.003. Disputed.\nThe delay is literal (ev_0064).",
          "QU claim 24 says no RC4 use is traced. Disputed.",
        ],
      },
      { title: "Findings", items: ["Gated init: the export loops resident only on success."] },
    ]);
    expect(parsed.prose).toBe("# DYNAMIC ANALYST, round 1 (revised)\n\n- **Citation scope.** I re-read ev_0064.");
  });

  it("reads the convergence signal as a note, not a list", () => {
    const parsed = parseAgentReport(
      [
        "[SCANNER ANALYST — round 3]",
        "Domain: x | Mean confidence: 0.75",
        "  Claim 1: A. | Evidence: ev_0001 | Confidence: 0.9",
        "  [CONVERGENCE SIGNAL: no remaining disputes]",
        "Written in this answer besides its claims:",
        "DISPUTES",
      ].join("\n"),
    );
    expect(parsed.claims).toHaveLength(1);
    expect(parsed.lists).toEqual([]);
    expect(parsed.signals).toEqual(["CONVERGENCE SIGNAL: no remaining disputes"]);
    expect(parsed.prose).toBe("DISPUTES");
  });

  it("reads a report of any other shape as prose", () => {
    const parsed = parseAgentReport("[ERROR] dynamic: sandbox unreachable");
    expect(parsed.claims).toEqual([]);
    expect(parsed.author).toBe("");
    expect(parsed.prose).toBe("[ERROR] dynamic: sandbox unreachable");
  });
});
