import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import SafeMarkdown from "../SafeMarkdown";
import {
  MAX_MARKDOWN_CHARS,
  inlineText,
  keepBackslashes,
  parseMarkdown,
  plainText,
  safeHref,
  subsectionTitles,
  type MdNode,
} from "../safeMarkdown";

/**
 * The bundle's Markdown is read by markdown-it as the report's renderer reads
 * it, drawn as a tree of strings and never as HTML, links only where the
 * report links, and in bounded depth and time whatever the input.
 */

/** Every link target the tree draws, in document order. */
function hrefs(nodes: readonly MdNode[]): string[] {
  const out: string[] = [];
  const stack = [...nodes].reverse();
  while (stack.length > 0) {
    const n = stack.pop()!;
    if (n.t !== "el") continue;
    if (n.tag === "a" && n.href) out.push(n.href);
    for (let i = n.c.length - 1; i >= 0; i--) stack.push(n.c[i]);
  }
  return out;
}

function html(markdown: string, extra: Record<string, unknown> = {}): string {
  return renderToStaticMarkup(createElement(SafeMarkdown, { markdown, ...extra }));
}

describe("a link is made only where the report makes one", () => {
  it("keeps a place in the bundle and the web's and mail's schemes", () => {
    expect(hrefs(parseMarkdown("[a](#ev_0007) [b](https://attack.mitre.org/techniques/T1027/) [c](mailto:soc@example.com)"))).toEqual([
      "#ev_0007",
      "https://attack.mitre.org/techniques/T1027/",
      "mailto:soc@example.com",
    ]);
  });

  it("keeps only the fragment of a link into the bundle file", () => {
    expect(hrefs(parseMarkdown("[n](evidence-bundle.html#cite-3)"))).toEqual(["#cite-3"]);
    expect(hrefs(parseMarkdown("[x](evidence-bundle.html#javascript:alert(1))")).every((h) => h.startsWith("#"))).toBe(true);
  });

  it.each([
    ["a script target", "[a](javascript:alert(1))"],
    ["a script target in mixed case", "[a](JaVaScRiPt:alert(1))"],
    ["a data target", "[a](data:text/html,<script>x</script>)"],
    ["a vbscript target", "[a](vbscript:msgbox(1))"],
    ["a control character before the scheme", "[a](\x01javascript:alert(1))"],
    ["a space before the scheme", "[a]( javascript:alert(1))"],
    ["a tab before the scheme", "[a](\tjavascript:alert(1))"],
    ["a script target in angle brackets", "[a](<javascript:alert(1)>)"],
    ["a script autolink", "<javascript:alert(1)>"],
    ["an upper-case script autolink", "<JAVASCRIPT:alert(1)>"],
    ["a data autolink", "<data:text/html,x>"],
    ["a character reference", "[a](&#106;avascript:alert(1))"],
    ["a protocol-relative target", "[a](//evil.example/)"],
    ["a relative file", "[a](report.html)"],
    ["a reference link to a script", "[a][r]\n\n[r]: javascript:alert(1)"],
    ["a script behind an image inside a link", "[![x](https://ok.example/i.png)](javascript:alert(1))"],
    ["a raw anchor tag", '<a href="javascript:x">x</a>'],
  ])("refuses %s", (_, markdown) => {
    expect(hrefs(parseMarkdown(markdown))).toEqual([]);
    expect(html(markdown)).not.toMatch(/<a\s/);
  });

  it("follows a reference link to an allowed target", () => {
    expect(hrefs(parseMarkdown("[a][r]\n\n[r]: https://ok.example/"))).toEqual(["https://ok.example/"]);
  });

  it("draws an image as its alt text and fetches nothing, inside a link too", () => {
    const markup = html("![beacon](https://evil.example/pixel.png) [![inner](https://evil.example/i.png)](https://ok.example/)");
    expect(markup).not.toContain("<img");
    expect(markup).not.toContain("evil.example");
    expect(markup).toContain("beacon");
    expect(markup).toContain('<a href="https://ok.example/"');
    expect(markup).toContain("inner");
  });

  it("opens a web link apart from the console and a place in the page in it", () => {
    const markup = html("[t](https://ok.example/) [r](#ev_0001)");
    expect(markup).toContain('rel="noopener noreferrer nofollow"');
    expect(markup).toContain('<a href="#ev_0001" class=');
    expect(safeHref(" https://ok.example/")).toBeNull();
  });
});

describe("a tag in the report's text stays text", () => {
  it("keeps markup as characters, escaped", () => {
    const markup = html('<script>alert("x")</script>\n\n<img src=x onerror=alert(1)>\n\nA <b>bold</b> word');
    expect(markup).not.toMatch(/<script|<img|<b>/i);
    expect(markup).toContain("&lt;script&gt;");
    expect(markup).toContain("&lt;img src=x onerror=alert(1)&gt;");
  });
});

describe("what is drawn", () => {
  it("reads emphasis, code spans, escapes, strikethrough and evidence ids", () => {
    const [p] = parseMarkdown("**Verdict:** Malware · _Source per row_ `a|b` \\*not\\* ~~gone~~ [ev_0014, ev_0018] `ev_0001`");
    expect(plainText([p])).toBe("Verdict: Malware · Source per row a|b *not* gone [ev_0014, ev_0018] ev_0001");
    expect(hrefs([p])).toEqual(["#ev_0014", "#ev_0018"]);
  });

  it("keeps a citation group whole as text when the page draws its own marks", () => {
    const nodes = parseMarkdown("It beacons **twice** [ev_0014, ev_0018].", { linkIds: false });
    expect(hrefs(nodes)).toEqual([]);
    const texts = JSON.stringify(nodes);
    expect(texts).toContain("[ev_0014, ev_0018]");
    // The bracket is one text run, so the citation splitter sees the group.
    expect(plainText(nodes)).toBe("It beacons twice [ev_0014, ev_0018].");
  });

  it("leaves an underscore inside a word alone", () => {
    expect(inlineText("api_capability and get_file_report")).toBe("api_capability and get_file_report");
  });

  it("reads a table with escaped pipes and aligned columns", () => {
    const markup = html("| ID | Value |\n|---|---:|\n| ev_0001 | `a\\|b` |");
    expect(markup).toContain("<table");
    expect(markup).toContain("a|b");
    expect(markup).toContain("text-align:right");
  });

  it("keeps a listing's text whole", () => {
    expect(parseMarkdown("```text\n<b>not bold</b>\n  indented\n```")).toEqual([{ t: "pre", v: "<b>not bold</b>\n  indented" }]);
  });

  it("draws a tight list item's words in the item", () => {
    expect(html("- one\n- two")).toMatch(/<li[^>]*>one<\/li>/);
  });
});

describe("a character reference in a link's target is read as the server reads it", () => {
  it("is decoded first, so a spelled-out scheme is still the scheme", () => {
    expect(hrefs(parseMarkdown("[a](https&#58;//evil.com)"))).toEqual(["https://evil.com"]);
  });

  it("stays text when the writer escaped its ampersand", () => {
    const nodes = parseMarkdown("[a](https\\&#58;//evil.com)");
    expect(hrefs(nodes)).toEqual([]);
    expect(plainText(nodes)).toBe("[a](https&#58;//evil.com)");
  });
});

describe("nothing past markdown-it's nesting bound is lost", () => {
  const list = (depth: number) =>
    Array.from({ length: depth }, (_, k) => " ".repeat(2 * k) + `- L${k}`).join("\n") + "\n\nAFTER";

  it.each([
    ["a quote nested 25 deep", ">".repeat(25) + " SECRET\n" + ">".repeat(25) + " MORE\n\nAFTER", ["SECRET", "MORE", "AFTER"]],
    ["a list nested 10 deep", list(10), ["L9", "AFTER"]],
    ["a list nested 12 deep", list(12), ["L11", "AFTER"]],
    ["a list nested 30 deep", list(30), ["L29", "AFTER"]],
  ])("keeps the inner text and what follows %s", (_, markdown, kept) => {
    const text = plainText(parseMarkdown(markdown));
    for (const word of kept) expect(text).toContain(word);
    const markup = html(markdown);
    for (const word of kept) expect(markup).toContain(word);
  });

  it("lays out a document that stays inside the bound", () => {
    expect(parseMarkdown(">".repeat(5) + " shallow\n\nAFTER")[0]).toMatchObject({ t: "el", tag: "blockquote" });
  });
});

describe("subsections", () => {
  const md = "### 5.1 Packing · _Source per row_\n\n```\n### not a heading\n```\n\n> ### Quoted\n\n- ### In a list\n\n### Process tree";

  it("are the top-level third-level headings only", () => {
    expect(subsectionTitles(md)).toEqual(["5.1 Packing · Source per row", "Process tree"]);
  });

  it("take the anchors in the same order, and a quoted heading takes none", () => {
    const markup = html(md, { subsectionIds: ["sec-packing", "sec-process-tree"] });
    expect(markup).toMatch(/<h4 id="sec-packing"/);
    expect(markup).toMatch(/<h4 id="sec-process-tree"/);
    expect(markup).toMatch(/<h4 class="[^"]*">Quoted<\/h4>/);
    expect(markup.match(/ id="/g)).toHaveLength(2);
  });
});

/* The inputs that drove a hand-written reader into deep recursion or
 * quadratic time, each built to about `size` characters. */
function repeatTo(unit: string, size: number): string {
  return unit.repeat(Math.max(1, Math.floor(size / unit.length)));
}
const ADVERSARIAL: [string, (size: number) => string][] = [
  ["spaces inside a paragraph", (n) => "a" + " ".repeat(n - 4) + "b\nc"],
  ["one-word lines", (n) => Array(Math.floor(n / 5)).fill("word").join("\n")],
  ["spaces inside a heading", (n) => "# a" + " ".repeat(n - 4) + "b"],
  ["a table delimiter with trailing spaces", (n) => "a|b\n|---" + " ".repeat(n - 10) + "x"],
  ["unclosed stars", (n) => repeatTo("*a ", n)],
  ["unclosed brackets", (n) => repeatTo("[", n)],
  ["stars and backticks", (n) => repeatTo("*a `", n)],
  ["unclosed strikethrough", (n) => repeatTo("~~a ", n)],
  ["backtick runs", (n) => repeatTo(Array.from({ length: 299 }, (_, k) => "`".repeat(k + 1) + "x").join(""), n)],
  ["nested link brackets", (n) => "[".repeat(Math.floor(n / 6)) + "a" + "](#x)".repeat(Math.floor(n / 6))],
  ["nested emphasis", (n) => "*_".repeat(Math.floor(n / 4)) + "a" + "_*".repeat(Math.floor(n / 4))],
  ["nested strong", (n) => "**".repeat(Math.floor(n / 4)) + "a" + "**".repeat(Math.floor(n / 4))],
  ["nested quotes", (n) => ">".repeat(n - 2) + " a"],
  ["nested lists", (n) => Array.from({ length: Math.floor(Math.sqrt(n) * 0.95) }, (_, k) => " ".repeat(2 * k) + "- a").join("\n")],
  ["unclosed autolinks", (n) => repeatTo("<a", n)],
  ["unclosed images", (n) => repeatTo("![", n)],
  ["unclosed link targets", (n) => repeatTo("[a](", n)],
];

/** Parses and draws `markdown`, failing on a throw; returns the parse time. */
function timed(markdown: string): number {
  let markup = "";
  // Best of three, so one stall on a shared runner does not read as slow input.
  let parsed = Infinity;
  for (let run = 0; run < 3; run += 1) {
    const start = performance.now();
    expect(() => {
      parseMarkdown(markdown);
      subsectionTitles(markdown);
    }).not.toThrow();
    parsed = Math.min(parsed, performance.now() - start);
  }
  expect(() => {
    markup = html(markdown);
  }).not.toThrow();
  expect(markup.length).toBeGreaterThan(0);
  return parsed;
}

describe("no input exhausts the stack or the clock", () => {
  // Warm the parser once, so the first case does not pay for compiling it.
  parseMarkdown("*a* **b** [c](#d) ![e](f) `g`\n\n> h\n\n- i");

  it.each(ADVERSARIAL)("reads %s at 200 KB, shown raw above the cap, in under 200 ms", (_, build) => {
    const markdown = build(200_000);
    expect(markdown.length).toBeGreaterThan(MAX_MARKDOWN_CHARS);
    expect(timed(markdown)).toBeLessThan(200);
    expect(html(markdown).startsWith("<pre")).toBe(true);
  });

  it.each(ADVERSARIAL)("parses %s just under the cap in under 200 ms", (_, build) => {
    const markdown = build(MAX_MARKDOWN_CHARS - 100);
    expect(markdown.length).toBeLessThanOrEqual(MAX_MARKDOWN_CHARS);
    expect(timed(markdown)).toBeLessThan(200);
  });

  it("shows a document above the cap as its raw text", () => {
    const markdown = "**x** ".repeat(Math.ceil(MAX_MARKDOWN_CHARS / 6) + 10);
    const markup = html(markdown);
    expect(markup.startsWith("<pre")).toBe(true);
    expect(markup).not.toContain("<strong");
    expect(subsectionTitles(markdown)).toEqual([]);
  });
});

describe("a model's backslashes", () => {
  const draw = (markdown: string) => plainText(parseMarkdown(keepBackslashes(markdown)));

  it("survive the Markdown reading in prose: a format string, a UNC path, a path with a star", () => {
    const literal = String.raw`init -zzzz="%s\%s" from \\server\share and C:\Users\*\AppData`;
    expect(draw(literal)).toContain(literal);
  });

  it("are left alone in a code span and a fenced block, which keep them already", () => {
    expect(keepBackslashes(String.raw`a \% b ` + "`c \\% d`")).toBe(String.raw`a \\\% b ` + "`c \\% d`");
    const fenced = ["```", String.raw`x\%y`, "```", String.raw`p\%q`].join("\n");
    expect(keepBackslashes(fenced)).toBe(["```", String.raw`x\%y`, "```", String.raw`p\\\%q`].join("\n"));
  });

  it("do not touch Markdown that has none", () => {
    expect(keepBackslashes("- **bold** and _em_")).toBe("- **bold** and _em_");
  });
});
