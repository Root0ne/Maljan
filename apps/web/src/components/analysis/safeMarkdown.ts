/**
 * The evidence bundle's Markdown, read into a tree the console draws as
 * React elements.
 *
 * The bundle's sections are the report's Markdown, and the report's text is
 * model- and sample-written. The reading is markdown-it's, set up as the
 * report's own HTML renderer sets up its Python port: the CommonMark preset
 * with tables and strikethrough, `html: false` (a tag in the text stays the
 * text it is), no bare-text links, a link made only where `safeHref` allows
 * one, and an image drawn as its alt text, never fetched. markdown-it bounds
 * its own nesting (`maxNesting`) and parses in linear time, so no input can
 * exhaust the stack or the clock here.
 *
 * Nothing here produces HTML: the token stream becomes a tree whose leaves
 * are strings React escapes. A bare evidence id in text is a link to its row
 * of the evidence index, which is what the bundle's HTML gives it.
 */

import MarkdownIt from "markdown-it";

export type Align = "left" | "right" | "center" | null;

export type MdNode =
  | { t: "text"; v: string }
  | { t: "br" }
  | { t: "code"; v: string }
  | { t: "pre"; v: string }
  | { t: "hr" }
  | {
      t: "el";
      tag: string;
      c: MdNode[];
      href?: string;
      start?: number;
      align?: Align;
      /** A third-level heading at the document's top level: a subsection,
       *  which takes the bundle's anchor (`subsectionTitles`). */
      sub?: boolean;
    };

/** The bundle's own file name, which a link into it may still carry. */
const BUNDLE_FILE = "evidence-bundle.html";
const LINKED_SCHEMES = ["http:", "https:", "mailto:"];
const EVIDENCE_ID = /\bev_\d+\b/g;

/** Above this many characters a section is shown as its raw text, and no
 *  parse is spent on it. The longest section a stored run's bundle draws is
 *  under 80 000 characters; at this size the costliest input markdown-it
 *  reads (deeply nested emphasis) still parses in well under 200 ms. */
export const MAX_MARKDOWN_CHARS = 100_000;

/** The deepest an element is nested in the tree: emphasis markdown-it pairs
 *  after its own nesting bound is applied can run deeper, and what lies
 *  below this depth is kept as text in the element at it. */
const MAX_DEPTH = 24;

/**
 * The target a link is drawn with, or null when the report makes no link of
 * it: a place in the bundle (a link into the bundle file keeps only its
 * fragment), or an http, https or mailto address, and never a
 * protocol-relative one.
 *
 * The `&` check refuses a target that still holds an ampersand when it gets
 * here. markdown-it decodes a character reference in a link's target before
 * it asks, as the server's renderer does, so `[a](https&#58;//x)` reaches
 * this as `https://x` and is a link on both; a reference the writer escaped
 * (`\&#58;`) arrives with its `&` and stays text. Hardening the server's
 * side of that is tracked apart.
 */
export function safeHref(url: string): string | null {
  const target = String(url ?? "");
  if (!target || target !== target.trim() || target.includes("&")) return null;
  if (target.startsWith("#")) return target;
  if (target.startsWith(`${BUNDLE_FILE}#`)) return target.slice(BUNDLE_FILE.length);
  const lower = target.toLowerCase();
  return LINKED_SCHEMES.some((scheme) => lower.startsWith(scheme)) ? target : null;
}

const md = new MarkdownIt("commonmark", { html: false, linkify: false }).enable(["table", "strikethrough"]);
// The link rule asks this of every link and autolink target, after
// markdown-it has normalised it; a target it refuses stays text.
md.validateLink = (url: string) => safeHref(url) !== null;

/**
 * The same reading for a model's prose that quotes paths and format strings
 * (`%s\%s`, `\\server\share`, `C:\Users\*\AppData`): every backslash escape
 * the inline pass reads is kept as written, backslash included, instead of
 * standing for the character after it. The escaped character is still
 * consumed by the escape, so a `\*` or `\_` opens no emphasis. Only the
 * escape rule's own tokens change: a code span, a link's target and an
 * autolink never reach it, and a backslash before a line break is still a
 * hard break. The cost is the rare escape a model meant (`\*`), which shows
 * its backslash.
 */
const literal = new MarkdownIt("commonmark", { html: false, linkify: false }).enable(["table", "strikethrough"]);
literal.validateLink = (url: string) => safeHref(url) !== null;
// A backslash before a run of `_` or `*` (`\__init__`) keeps the whole run as
// text, so the rest of the run opens no emphasis either.
literal.inline.ruler.before("escape", "keep_escaped_run", (state, silent) => {
  if (state.src.charCodeAt(state.pos) !== 0x5c) return false;
  const mark = state.src[state.pos + 1];
  if (mark !== "_" && mark !== "*") return false;
  let end = state.pos + 1;
  while (end < state.posMax && state.src[end] === mark) end++;
  if (!silent) state.push("text", "", 0).content = state.src.slice(state.pos, end);
  state.pos = end;
  return true;
});
literal.core.ruler.before("text_join", "keep_backslashes", (state) => {
  for (const block of state.tokens) {
    for (const token of block.children ?? []) {
      if (token.type === "text_special" && token.info === "escape") token.content = token.markup;
    }
  }
});

// The same reading without the inline pass: the block structure only, which
// is all the subsections are found by, in linear time and whatever the size.
const blocks = new MarkdownIt("commonmark", { html: false, linkify: false }).enable(["table", "strikethrough"]);
blocks.validateLink = md.validateLink;
blocks.core.ruler.disable("inline");

type Token = ReturnType<typeof md.parse>[number];

/** The one rule a subsection is found by: a third-level heading at the
 *  document's top level, never one inside a quote or a list. */
function isSubsection(token: Token): boolean {
  return token.type === "heading_open" && token.tag === "h3" && token.level === 0;
}

/** The words of a run of nodes, without their marks. */
export function plainText(nodes: readonly MdNode[]): string {
  let out = "";
  const stack: MdNode[] = [...nodes].reverse();
  while (stack.length > 0) {
    const n = stack.pop()!;
    if (n.t === "text" || n.t === "code" || n.t === "pre") out += n.v;
    else if (n.t === "br") out += " ";
    else if (n.t === "el") for (let i = n.c.length - 1; i >= 0; i--) stack.push(n.c[i]);
  }
  return out;
}

/** The text of an image token: its alt, which is all of it the reader gets. */
function altText(token: Token): string {
  return (token.children ?? []).map((c) => c.content).join("") || token.content;
}

function alignOf(token: Token): Align {
  const style = String(token.attrGet("style") ?? "");
  const m = /text-align:\s*(left|right|center)/.exec(style);
  return m ? (m[1] as Align) : null;
}

/** Pushes text, linking each bare evidence id outside a link. */
function pushText(out: MdNode[], text: string, inLink: boolean): void {
  if (!text) return;
  if (inLink) {
    out.push({ t: "text", v: text });
    return;
  }
  let last = 0;
  for (const m of text.matchAll(EVIDENCE_ID)) {
    const at = m.index ?? 0;
    if (at > last) out.push({ t: "text", v: text.slice(last, at) });
    out.push({ t: "el", tag: "a", href: `#${m[0]}`, c: [{ t: "text", v: m[0] }] });
    last = at + m[0].length;
  }
  if (last < text.length) out.push({ t: "text", v: text.slice(last) });
}

/**
 * A flat token stream as a tree, with an explicit stack: an open token
 * starts an element, its close ends it, and an inline token's children are
 * read the same way into the element it stands in.
 */
function buildTree(tokens: readonly Token[], linkIds = true): MdNode[] {
  const root: MdNode[] = [];
  const stack: { node: Extract<MdNode, { t: "el" }> | null; c: MdNode[]; link: boolean }[] = [
    { node: null, c: root, link: false },
  ];
  // Opens past MAX_DEPTH, flattened into the element at it; their closes
  // are matched off against this count before any element is closed.
  let flattened = 0;
  const top = () => stack[stack.length - 1];
  const open = (token: Token, level: number) => {
    if (stack.length > MAX_DEPTH) {
      flattened++;
      return;
    }
    const node: Extract<MdNode, { t: "el" }> = { t: "el", tag: token.tag, c: [] };
    if (token.type === "link_open") {
      const href = safeHref(String(token.attrGet("href") ?? ""));
      // The link rule has already refused every other target; a link it let
      // through and this refuses is drawn as its text.
      if (href) node.href = href;
      else node.tag = "span";
    }
    if (token.type === "ordered_list_open") {
      const start = Number(token.attrGet("start") ?? 1);
      node.start = Number.isFinite(start) ? start : 1;
    }
    if (token.type === "th_open" || token.type === "td_open") node.align = alignOf(token);
    if (level === 0 && isSubsection(token)) node.sub = true;
    top().c.push(node);
    stack.push({ node, c: node.c, link: top().link || token.type === "link_open" });
  };
  const walk = (list: readonly Token[], inline: boolean) => {
    for (const token of list) {
      // A tight list item's paragraph is hidden: its words sit in the item.
      if (token.hidden && token.nesting !== 0) continue;
      if (token.nesting === 1) {
        open(token, inline ? -1 : token.level);
      } else if (token.nesting === -1) {
        if (flattened > 0) flattened--;
        else if (stack.length > 1) stack.pop();
      } else if (token.type === "inline") {
        walk(token.children ?? [], true);
      } else if (token.type === "text") {
        pushText(top().c, token.content, top().link || !linkIds);
      } else if (token.type === "code_inline") {
        top().c.push({ t: "code", v: token.content });
      } else if (token.type === "softbreak") {
        top().c.push({ t: "text", v: "\n" });
      } else if (token.type === "hardbreak") {
        top().c.push({ t: "br" });
      } else if (token.type === "fence" || token.type === "code_block") {
        top().c.push({ t: "pre", v: token.content.replace(/\n$/, "") });
      } else if (token.type === "hr") {
        top().c.push({ t: "hr" });
      } else if (token.type === "image") {
        pushText(top().c, altText(token), true);
      } else if (token.content) {
        // Anything else carries text and nothing a reader is owed beyond it.
        pushText(top().c, token.content, true);
      }
    }
  };
  walk(tokens, false);
  return root;
}

/**
 * A Markdown document, as a tree of strings and elements.
 *
 * `linkIds: false` leaves a bare evidence id in the text as text: report
 * prose outside the bundle draws its citations as marks that open the
 * evidence drawer (`CitedProse`), not as anchors into a bundle that is not
 * on the page. `keepBackslashes` reads it with every backslash escape kept
 * as written (`literal`).
 */
export function parseMarkdown(
  markdown: string,
  { linkIds = true, keepBackslashes = false }: { linkIds?: boolean; keepBackslashes?: boolean } = {},
): MdNode[] {
  if (markdown.length > MAX_MARKDOWN_CHARS) return [{ t: "pre", v: markdown }];
  const tokens = (keepBackslashes ? literal : md).parse(markdown, {});
  // At its nesting bound markdown-it stops reading the container it is in,
  // and every line after that point is dropped. A document that reached it
  // is shown as its raw text, so nothing in it is lost.
  if (reachedNestingBound(tokens)) return [{ t: "pre", v: markdown }];
  return buildTree(tokens, linkIds);
}

/** Whether a block token stands at the deepest level markdown-it reads. */
function reachedNestingBound(tokens: readonly Token[]): boolean {
  const bound = Number(md.options.maxNesting) - 1;
  return tokens.some((token) => token.level >= bound);
}

/** One line of inline Markdown (a title), as its words. */
export function inlineText(markdown: string): string {
  if (markdown.length > MAX_MARKDOWN_CHARS) return markdown;
  return plainText(buildTree(md.parseInline(markdown, {})));
}

/**
 * The titles of a document's subsections, in order, without their marks:
 * its third-level headings at the top level (never one inside a quote or a
 * list), which is the one rule `parseMarkdown` marks them by. The bundle's
 * anchors for its subsections are built from these.
 */
export function subsectionTitles(markdown: string): string[] {
  // The block structure alone, whatever the size: a section too long to be
  // laid out still gives its subsections the anchors the bundle's HTML does.
  const tokens = blocks.parse(markdown, {});
  const titles: string[] = [];
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i];
    if (isSubsection(token)) titles.push(inlineText(tokens[i + 1]?.content ?? ""));
  }
  return titles;
}
