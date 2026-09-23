/**
 * The one severity ladder, and the guard that keeps it the only one.
 *
 * A sort by label puts High, Informational, Low and Medium in that order,
 * which is the alphabet; a second colour map is how Medium came to be purple
 * on one tab and blue on the next. The first half pins the ladder, the second
 * reads the tree for anything that compares or colours a rung on its own.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import {
  SEVERITY_LADDER,
  atLeast,
  bySeverityDesc,
  NEUTRAL_TONE,
  ladderDots,
  signatureScore,
  severityRank,
  severityRung,
  severityTone,
  severityWord,
  sortBySeverity,
} from "@/lib/severity";

describe("the severity ladder", () => {
  it("ranks the judge's five words from Critical down to Informational", () => {
    expect(SEVERITY_LADDER.map(severityRank)).toEqual([4, 3, 2, 1, 0]);
  });

  it("reads a rung in any case, and gives a word that is not a rung no rank", () => {
    expect(severityRung("critical")).toBe("Critical");
    expect(severityRung(" HIGH ")).toBe("High");
    expect(severityRung("severe")).toBeNull();
    expect(severityRank("severe")).toBe(-1);
    expect(severityRank(null)).toBe(-1);
  });

  it("sorts by rank, never by the label's alphabetical order", () => {
    const labels = ["High", "Informational", "Low", "Medium", "Critical"];
    expect([...labels].sort()).toEqual(["Critical", "High", "Informational", "Low", "Medium"]);
    expect([...labels].sort(bySeverityDesc)).toEqual([
      "Critical",
      "High",
      "Medium",
      "Low",
      "Informational",
    ]);
  });

  it("keeps equal rungs in the order they arrived and puts unknown words last", () => {
    const rows = [
      { id: "a", severity: "low" },
      { id: "b", severity: "unrated" },
      { id: "c", severity: "high" },
      { id: "d", severity: "Low" },
    ];
    expect(sortBySeverity(rows, (r) => r.severity).map((r) => r.id)).toEqual(["c", "a", "d", "b"]);
  });

  it("draws one dot per rung from Informational up, and none off the ladder", () => {
    expect(SEVERITY_LADDER.map(ladderDots)).toEqual([5, 4, 3, 2, 1]);
    expect(ladderDots("low")).not.toBe(ladderDots("informational"));
    expect(ladderDots("unrated")).toBe(0);
    expect(ladderDots(null)).toBe(0);
  });

  it("answers at-or-above against the ladder", () => {
    expect(atLeast("Critical", "High")).toBe(true);
    expect(atLeast("high", "High")).toBe(true);
    expect(atLeast("Medium", "High")).toBe(false);
    expect(atLeast("assessed none", "Informational")).toBe(false);
  });

  it("colours every rung, and anything else as Informational", () => {
    expect(severityTone("Critical").text).toBe("text-status-red");
    expect(severityTone("medium").text).toBe("text-status-purple");
    expect(severityTone("Low").text).toBe("text-status-blue");
    expect(severityTone("unrated")).toEqual(severityTone("Informational"));
    expect(severityTone(undefined)).toEqual(severityTone("Informational"));
  });

  it("prints a rung in its own spelling and any other word as it arrived", () => {
    expect(severityWord("critical")).toBe("Critical");
    expect(severityWord("unrated")).toBe("unrated");
  });

  it("reads a CAPE signature on CAPE's 1 to 3 scale", () => {
    expect(signatureScore(1, "cape2")).toMatchObject({ rung: "Low", label: "1/3" });
    expect(signatureScore(2, "cape2")).toMatchObject({ rung: "Medium", label: "2/3" });
    expect(signatureScore(3, "cape2")).toMatchObject({ rung: "High", label: "3/3" });
    expect(signatureScore(3, "cape2").tone).toEqual(severityTone("High"));
  });

  it("reads a Triage signature on Triage's 1 to 10 scale", () => {
    expect(signatureScore(1, "triage").rung).toBe("Informational");
    expect(signatureScore(3, "triage").rung).toBe("Low");
    expect(signatureScore(6, "triage").rung).toBe("Medium");
    expect(signatureScore(8, "triage")).toMatchObject({ rung: "High", label: "8/10" });
    expect(signatureScore(10, "triage").rung).toBe("Critical");
  });

  it("draws a number whose scale is not known in one neutral tone, as it came", () => {
    // An uploaded report can be either sandbox's, so its provider says nothing
    // about the scale.
    for (const provider of ["upload", "rest", "mock", "", null]) {
      expect(signatureScore(8, provider)).toEqual({
        tone: NEUTRAL_TONE,
        rung: null,
        label: "8",
        scale: null,
      });
    }
  });

  it("draws a number outside its provider's scale neutrally, not at the scale's top", () => {
    expect(signatureScore(8, "cape2")).toMatchObject({ tone: NEUTRAL_TONE, rung: null, label: "8" });
    expect(signatureScore(0, "triage").rung).toBeNull();
  });
});

const SRC = path.resolve(__dirname, "..", "..");
const LADDER = path.join(SRC, "lib", "severity.ts");

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name !== "__tests__") out.push(...sourceFiles(full));
      continue;
    }
    if (/\.tsx?$/.test(name) && full !== LADDER) out.push(full);
  }
  return out;
}

const RUNG = "(?:[Cc]ritical|[Hh]igh|[Mm]edium|[Ll]ow|[Ii]nformational)";

const GUARDS: { what: string; pattern: RegExp }[] = [
  {
    // `Critical: { text: "text-status-red" … }` or `critical: "bg-status-red"`.
    what: "a severity rung given a status colour",
    pattern: new RegExp(`\\b${RUNG}\\s*:\\s*(?:\\{[^}]*?)?["'\`][^"'\`\\n]*\\b(?:text|bg|border)-status-`, "g"),
  },
  {
    // `rule.severity === "critical"`, `level !== "High"`: a rung compared by
    // its spelling, which is how a ladder gets a second, private order.
    what: "a severity rung compared by its label",
    pattern: new RegExp(
      `(?:severity|rating|level|sev)[\\w.?\\]\\[]*\\s*[!=]==?\\s*["']${RUNG}["']`,
      "gi",
    ),
  },
  {
    // The same comparison written the other way round.
    what: "a severity rung compared by its label, reversed",
    pattern: new RegExp(`["']${RUNG}["']\\s*[!=]==?\\s*[\\w.?]*(?:severity|rating|level|sev)`, "gi"),
  },
  {
    // `switch (sev) { case "Critical": … }`: a colour or an order per rung,
    // kept outside the ladder.
    what: "a severity rung switched on",
    pattern: new RegExp(`\\bcase\\s+["']${RUNG}["']\\s*:`, "g"),
  },
  {
    what: "a severity sorted by its label",
    pattern: /(?:severity|rating|level)[^\n]*localeCompare/gi,
  },
  {
    // `a.rating > b.rating`: the alphabet again, through a comparison sort.
    what: "a severity sorted by comparing labels",
    pattern: /\.(?:severity|rating|level)\s*[<>]=?\s*\w+\.(?:severity|rating|level)\b/gi,
  },
];

describe("the severity guard's own reach", () => {
  const hits = (what: string, text: string) =>
    [...text.matchAll(GUARDS.find((g) => g.what === what)!.pattern)].length;

  it("catches the shapes a second ladder is written in", () => {
    expect(hits("a severity rung compared by its label", 'if (level === "High")')).toBe(1);
    expect(hits("a severity rung compared by its label", 'rule.severity !== "critical"')).toBe(1);
    expect(hits("a severity rung compared by its label, reversed", '"Low" === item.rating')).toBe(1);
    expect(hits("a severity rung switched on", 'switch (sev) { case "Critical": return "x"; }')).toBe(1);
    expect(hits("a severity sorted by comparing labels", "(a, b) => (a.rating > b.rating ? 1 : -1)")).toBe(1);
  });

  it("leaves a word that is not a rung, and a numeric score, alone", () => {
    expect(hits("a severity rung compared by its label", 'w.severity === "error"')).toBe(0);
    expect(hits("a severity sorted by comparing labels", "b.severity - a.severity")).toBe(0);
  });
});

describe("severity is compared and coloured in one place", () => {
  const files = sourceFiles(SRC);

  it("reads the whole tree, so a pass means something", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  for (const guard of GUARDS) {
    it(`finds no ${guard.what} outside lib/severity.ts`, () => {
      const offenders: string[] = [];
      for (const file of files) {
        const body = readFileSync(file, "utf8");
        for (const match of body.matchAll(guard.pattern)) {
          const line = body.slice(0, match.index ?? 0).split("\n").length;
          offenders.push(`${path.relative(SRC, file)}:${line} — ${match[0].slice(0, 60)}`);
        }
      }
      expect(offenders).toEqual([]);
    });
  }
});
