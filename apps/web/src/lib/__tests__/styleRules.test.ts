/**
 * The style rules, kept by a test rather than by remembering them.
 *
 * Three of them, and each has been broken by a single copied class before:
 * no gradient anywhere, no colour or background that eases from one value to
 * another, and no backdrop blur. A hover state is a state, so it arrives when
 * the pointer does; a 150 ms fade on a border is a small lie about when the
 * thing became hoverable.
 *
 * It reads the tree rather than the built CSS, because a class that is never
 * rendered is still a class somebody will copy.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const SRC = path.resolve(__dirname, "..", "..");

/** Every file under `src` the rules apply to, this test excepted. */
function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) {
      out.push(...sourceFiles(full));
      continue;
    }
    if (!/\.(tsx?|css)$/.test(name)) continue;
    if (full === __filename) continue;
    out.push(full);
  }
  return out;
}

interface Rule {
  what: string;
  /** Global so every hit in a file is reported, not only the first. */
  pattern: RegExp;
}

const RULES: Rule[] = [
  // Every Tailwind and CSS spelling of a gradient, plus the trick that paints
  // one through the text.
  { what: "gradient", pattern: /\b(bg|from|via|to)-gradient|gradient\(|\bbg-clip-text\b/g },
  {
    what: "gradient stop",
    // `from-`, `via-` and `to-` only ever name one in Tailwind; nothing else
    // in this tree spells a class that way.
    pattern: /\bclassName[^\n]*\b(from|via|to)-\[?(?:[a-z]+-)*[a-z0-9#(./]+/g,
  },
  // A chart draws its own surface: an SVG gradient is a gradient that no
  // class name spells, and a bar list or a pie is where one would be added.
  { what: "SVG gradient", pattern: /<(linear|radial)Gradient\b/g },
  { what: "colour transition", pattern: /\btransition-(colors|background|border)\b/g },
  {
    what: "colour transition by arbitrary property",
    pattern: /\btransition-\[[^\]]*(color|background|border|fill|stroke|shadow)[^\]]*\]/g,
  },
  {
    // `style={{ transition: "background 150ms" }}`: the same ease, written
    // where no class list would show it.
    what: "colour transition in an inline style",
    pattern: /\btransition(Property)?\s*:\s*["'`][^"'`]*(color|background|border|fill|stroke|all)\b/g,
  },
  {
    what: "colour transition in a stylesheet",
    pattern: /(^|[;{\s])transition(-property)?\s*:[^;"'`]*\b(color|background|border|fill|stroke|all)\b/gm,
  },
  { what: "transition of everything, which includes colour", pattern: /\btransition-all\b/g },
  { what: "backdrop blur", pattern: /\bbackdrop-blur\b/g },
];

describe("the style rules", () => {
  const files = sourceFiles(SRC);

  it("reads the whole tree, so a pass means something", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  for (const rule of RULES) {
    it(`finds no ${rule.what}`, () => {
      const offenders: string[] = [];
      for (const file of files) {
        const body = readFileSync(file, "utf8");
        for (const match of body.matchAll(rule.pattern)) {
          const line = body.slice(0, match.index ?? 0).split("\n").length;
          offenders.push(`${path.relative(SRC, file)}:${line} — ${match[0]}`);
        }
      }
      expect(offenders).toEqual([]);
    });
  }

  /* The console had no responsive layout at all: twenty-one unconditional
   * multi-column grids, so the dashboard kept four stat columns at 375 px and
   * clipped every one of their labels. The rule that replaced them is that the
   * base layout is the phone layout — at most two columns before a breakpoint
   * variant widens it — and this is what keeps a copied `grid-cols-4` from
   * bringing the old behaviour back. */
  it("gives every multi-column grid a phone layout", () => {
    const offenders: string[] = [];
    for (const file of files) {
      const body = readFileSync(file, "utf8");
      for (const match of body.matchAll(/(^|[^:\w-])grid-cols-(\d+)/g)) {
        if (Number(match[2]) <= 2) continue;
        const line = body.slice(0, match.index ?? 0).split("\n").length;
        offenders.push(`${path.relative(SRC, file)}:${line} — grid-cols-${match[2]}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  /* The transitions that stay: width, transform and opacity move something,
   * and a rail that widens or a chevron that turns is showing what changed
   * rather than colouring it. */
  it("leaves the transitions that move something", () => {
    const moving = files.filter((file) =>
      /\btransition-(transform|\[width\]|opacity)\b/.test(readFileSync(file, "utf8")),
    );
    expect(moving.length).toBeGreaterThan(0);
  });
});
