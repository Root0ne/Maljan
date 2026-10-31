import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The light theme's status tokens against the tinted chips they sit on. The
 * ratios are computed from the token values in globals.css, so a token moved
 * back below WCAG AA (4.5:1) fails here.
 */
const CSS = readFileSync(join(process.cwd(), "src/app/globals.css"), "utf8");
const LIGHT_AT = CSS.indexOf('html[data-ui-theme="light"] {');
const LIGHT_BLOCK = CSS.slice(LIGHT_AT, CSS.indexOf("}", LIGHT_AT));

function token(name: string): string {
  const m = new RegExp(`--${name}:\\s*(#[0-9a-fA-F]{6})`).exec(LIGHT_BLOCK);
  if (!m) throw new Error(`no light token ${name}`);
  return m[1];
}

function rgb(hex: string): [number, number, number] {
  return [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)) as [number, number, number];
}

function luminance(hex: string): number {
  const [r, g, b] = rgb(hex).map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function ratio(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** `fg` at `alpha` over `base`, as a hex colour. */
function over(fg: string, base: string, alpha: number): string {
  const f = rgb(fg);
  const b = rgb(base);
  return "#" + f.map((v, i) => Math.round(v * alpha + b[i] * (1 - alpha)).toString(16).padStart(2, "0")).join("");
}

describe("light theme contrast (AA, 4.5:1)", () => {
  const pairs: [string, string, string][] = [
    ["verdict Malicious", "status-red", "#f8dee0"],
    ["High 4/5 chip", "status-orange", "#f8ede6"],
    ["published badge", "status-green", "#e8f2eb"],
  ];

  for (const [what, name, bg] of pairs) {
    it(`${what}: ${name} on ${bg}`, () => {
      expect(ratio(token(name), bg)).toBeGreaterThanOrEqual(4.5);
    });
  }

  it.each(["status-red", "status-orange", "status-green"])("%s holds on its own 10% and 15% tint and on white", (name) => {
    for (const bg of [over(token(name), "#ffffff", 0.1), over(token(name), "#ffffff", 0.15), "#ffffff", "#f6f8fa"]) {
      expect(ratio(token(name), bg)).toBeGreaterThanOrEqual(4.5);
    }
  });

  it("leaves the dark theme's values alone", () => {
    const dark = CSS.slice(0, LIGHT_AT);
    for (const v of ["#b3202b", "#a64600", "#17702f"]) expect(dark).not.toContain(v);
  });
});
