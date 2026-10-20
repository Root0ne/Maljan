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
  runSignatureScale,
  signatureScore,
  bySignatureSeverity,
  severityRank,
  severityRung,
  severityTone,
  severityWord,
  sortBySeverity,
} from "@/lib/severity";

/** A run summary stored before scales were recorded: only its provider. */
function stored(provider: string | null) {
  return runSignatureScale({ settings_snapshot: { "sandbox.provider": provider } });
}

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

  it("reads a stored CAPE run's signature on the legacy CAPE 1 to 3 scale", () => {
    expect(signatureScore(1, stored("cape2"))).toMatchObject({ rung: "Low", label: "1/3" });
    expect(signatureScore(2, stored("cape2"))).toMatchObject({ rung: "Medium", label: "2/3" });
    expect(signatureScore(3, stored("cape2"))).toMatchObject({ rung: "High", label: "3/3" });
    expect(signatureScore(3, stored("cape2")).tone).toEqual(severityTone("High"));
    expect(signatureScore(2, stored("cape2")).text).toBe("Medium, 2/3");
  });

  it("reads a stored Triage run's signature on the legacy Triage 1 to 10 scale", () => {
    expect(signatureScore(1, stored("triage")).rung).toBe("Informational");
    expect(signatureScore(3, stored("triage")).rung).toBe("Low");
    expect(signatureScore(6, stored("triage")).rung).toBe("Medium");
    expect(signatureScore(8, stored("triage"))).toMatchObject({ rung: "High", label: "8/10", text: "High, 8/10" });
    expect(signatureScore(10, stored("triage")).rung).toBe("Critical");
  });

  it("draws a stored run's number whose scale is not known in one neutral tone, as it came", () => {
    // A stored uploaded report could be either sandbox's, so its provider says
    // nothing about the scale.
    for (const provider of ["upload", "rest", "mock", "", null]) {
      expect(signatureScore(8, stored(provider))).toEqual({
        tone: NEUTRAL_TONE,
        rung: null,
        label: "8",
        scale: null,
        text: "unrated, 8",
      });
    }
  });

  it("draws a number outside its provider's scale neutrally, not at the scale's top", () => {
    expect(signatureScore(8, stored("cape2"))).toMatchObject({ tone: NEUTRAL_TONE, rung: null, label: "8" });
    expect(signatureScore(0, stored("triage")).rung).toBeNull();
  });

  it("reads a run's recorded scale, whatever its provider", () => {
    const summary = {
      settings_snapshot: { "sandbox.provider": "upload" },
      sandbox_signature_scale: { name: "Acme 1–4", max: 4, rungs: ["Low", "Low", "High", "Critical"] },
    };
    const scale = runSignatureScale(summary);
    expect(scale).toEqual({ name: "Acme 1–4", max: 4, rungs: ["Low", "Low", "High", "Critical"] });
    expect(signatureScore(3, scale)).toMatchObject({ rung: "High", label: "3/4", text: "High, 3/4" });
    expect(signatureScore(4, scale).tone).toEqual(severityTone("Critical"));
  });

  it("draws a run that recorded no scale unrated, even where the legacy table has one", () => {
    const summary = { settings_snapshot: { "sandbox.provider": "cape2" }, sandbox_signature_scale: null };
    expect(runSignatureScale(summary)).toBeNull();
    expect(signatureScore(2, runSignatureScale(summary))).toMatchObject({ rung: null, text: "unrated, 2" });
  });

  it("reads a recorded scale whose rungs are not all ladder words as no scale", () => {
    for (const recorded of [
      { name: "x", max: 2, rungs: ["Low", "Severe"] },
      { name: "x", max: 3, rungs: ["Low", "High"] },
      { name: "x", max: 0, rungs: [] },
      { max: 1, rungs: ["Low"] },
      "Low",
    ]) {
      expect(runSignatureScale({ sandbox_signature_scale: recorded })).toBeNull();
    }
  });

  it("reads a recorded rung in any case in its own spelling", () => {
    const scale = runSignatureScale({ sandbox_signature_scale: { name: "x", max: 2, rungs: ["low", "HIGH"] } });
    expect(scale?.rungs).toEqual(["Low", "High"]);
  });

  it("reads a summary that is missing or carries no snapshot by the legacy table as no scale", () => {
    expect(runSignatureScale(null)).toBeNull();
    expect(runSignatureScale(undefined)).toBeNull();
    expect(runSignatureScale({})).toBeNull();
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

describe("a signature with no severity", () => {
  it("is drawn as unknown in the neutral tone, never as a number", () => {
    expect(signatureScore(null, stored("cape2"))).toMatchObject({
      tone: NEUTRAL_TONE,
      rung: null,
      label: "unknown",
      text: "unknown",
    });
    expect(signatureScore(null, null).text).toBe("unknown");
  });

  it("sorts below every number, zero included", () => {
    const rows = [
      { name: "a", severity: null },
      { name: "b", severity: 0 },
      { name: "c", severity: 3 },
      { name: "d", severity: null },
    ];
    expect([...rows].sort(bySignatureSeverity).map((r) => r.name)).toEqual(["c", "b", "a", "d"]);
  });
});
