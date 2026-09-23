/**
 * One colour per run status, and the guard that keeps it the only map.
 *
 * The search palette drew a running job orange while every other surface drew
 * it blue; each page had its own map and nothing held them together.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { progressTone, statusTone } from "@/lib/status";

describe("the run status colours", () => {
  it("colour each status once, whatever its case", () => {
    expect(statusTone("running").text).toBe("text-status-blue");
    expect(statusTone("RUNNING")).toEqual(statusTone("running"));
    expect(statusTone("completed").text).toBe("text-status-green");
    expect(statusTone("failed").text).toBe("text-status-red");
  });

  it("read a status they do not know as pending", () => {
    expect(statusTone("archived")).toEqual(statusTone("pending"));
    expect(statusTone(null)).toEqual(statusTone("pending"));
  });

  it("give a stage and a participant the run's colours for the same facts", () => {
    expect(progressTone("running")).toEqual(statusTone("running"));
    expect(progressTone("working")).toEqual(statusTone("running"));
    expect(progressTone("done")).toEqual(statusTone("completed"));
    expect(progressTone("skipped")).toEqual(statusTone("pending"));
  });
});

const SRC = path.resolve(__dirname, "..", "..");
const MODULE = path.join(SRC, "lib", "status.ts");

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) {
      if (name !== "__tests__") out.push(...sourceFiles(full));
      continue;
    }
    if (/\.tsx?$/.test(name) && full !== MODULE) out.push(full);
  }
  return out;
}

// Every word a run, a stage, a participant or an agent's answer uses for how it
// stands. `failed` is here too: the conversation's failed answer is coloured
// from the same map as a failed run, not from a second one.
const STATE = "(?:running|completed|working|done|pending|cancelled|failed)";

const GUARDS: { what: string; pattern: RegExp }[] = [
  {
    // `running: "text-status-blue"` or `running: { text: "text-status-blue" … }`.
    what: "a run or stage status given a status colour",
    pattern: new RegExp(`\\b${STATE}\\s*:\\s*(?:\\{[^}]*?)?["'\`][^"'\`\\n]*\\b(?:text|bg|border)-status-`, "g"),
  },
  {
    // `job.status === "running" ? "text-status-blue" : …`, on any variable,
    // either way round.
    what: "a status coloured by a comparison of its spelling",
    pattern: new RegExp(
      `(?:[\\w.?\\]\\[]+\\s*[!=]==?\\s*["']${STATE}["']|["']${STATE}["']\\s*[!=]==?\\s*[\\w.?\\]\\[]+)\\s*\\?\\s*["'\`][^"'\`\\n]*status-`,
      "g",
    ),
  },
];

describe("the status guard's own reach", () => {
  const hits = (index: number, text: string) => [...text.matchAll(GUARDS[index].pattern)].length;

  it("catches a map entry and a ternary on any variable, for every state word", () => {
    expect(hits(0, '{ failed: "text-status-red" }')).toBe(1);
    expect(hits(0, '{ cancelled: { text: "text-status-orange" } }')).toBe(1);
    expect(hits(1, 's === "running" ? "text-status-orange" : ""')).toBe(1);
    expect(hits(1, 'row.state === "cancelled" ? "bg-status-red/10" : ""')).toBe(1);
    expect(hits(1, '"failed" === x ? "text-status-red" : ""')).toBe(1);
  });

  it("leaves a word that is not a state, and a neutral colour, alone", () => {
    expect(hits(0, '{ error: "text-status-red" }')).toBe(0);
    expect(hits(1, 's === "running" ? "text-text-muted" : ""')).toBe(0);
  });
});

describe("run status is coloured in one place", () => {
  const files = sourceFiles(SRC);

  it("reads the whole tree, so a pass means something", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  for (const guard of GUARDS) {
    it(`finds no ${guard.what} outside lib/status.ts`, () => {
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
