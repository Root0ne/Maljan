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

const STATE = "(?:running|completed|working|done|pending|cancelled)";

const GUARDS: { what: string; pattern: RegExp }[] = [
  {
    // `running: "text-status-blue"` or `running: { text: "text-status-blue" … }`.
    what: "a run or stage status given a status colour",
    pattern: new RegExp(`\\b${STATE}\\s*:\\s*(?:\\{[^}]*?)?["'\`][^"'\`\\n]*\\b(?:text|bg|border)-status-`, "g"),
  },
  {
    // `job.status === "running" ? "text-status-blue" : …`.
    what: "a status coloured by a comparison of its spelling",
    pattern: /(?:status|state)\s*===\s*["'](?:running|completed|failed|done)["']\s*\?\s*["'`][^"'`\n]*status-/g,
  },
];

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
