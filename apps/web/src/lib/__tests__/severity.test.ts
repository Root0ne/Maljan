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
  scoreTone,
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

  it("colours a sandbox score from the same ladder, at the thresholds DYNAMIC used", () => {
    expect(scoreTone(8)).toEqual(severityTone("Critical"));
    expect(scoreTone(7)).toEqual(severityTone("Critical"));
    expect(scoreTone(4)).toEqual(severityTone("High"));
    expect(scoreTone(3)).toEqual(severityTone("Informational"));
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
    // `rule.severity === "critical"`: a rung compared by its spelling, which
    // is how a ladder gets a second, private order.
    what: "a severity rung compared by its label",
    pattern: new RegExp(`(?:severity|rating)[\\w.?]*\\s*[!=]==?\\s*["']${RUNG}["']`, "g"),
  },
  {
    what: "a severity sorted by its label",
    pattern: /(?:severity|rating)[^\n]*localeCompare/g,
  },
];

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
