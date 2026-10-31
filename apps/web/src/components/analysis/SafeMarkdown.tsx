"use client";

import { Component, Fragment, useMemo, type ReactNode } from "react";
import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
import CitedProse from "./CitedProse";
import { MAX_MARKDOWN_CHARS, parseMarkdown, type MdNode } from "./safeMarkdown";

/**
 * Bundle Markdown drawn as React elements, never as HTML (`safeMarkdown`).
 *
 * `subsectionIds` are the anchors the document's subsections get, in order
 * (`evidenceBundle.subsectionAnchors`), so a link to one lands here as it
 * lands in the bundle's HTML. `skipFirstHeading` leaves out the heading a
 * caller already draws as the section's title. A table or a listing wider
 * than the page scrolls inside its own box; the page never scrolls sideways.
 *
 * A document above `MAX_MARKDOWN_CHARS` is shown as its raw text, and so is
 * one whose drawing fails: the section stays readable and the page around
 * it stands.
 *
 * Every model-written text on the analysis page is drawn here. `cite` draws
 * the report's evidence citations as the page's one citation mark
 * (`CitedProse`) instead of anchors into the bundle; `inline` drops the
 * paragraph box around a one-paragraph text so it sits in a row or a line;
 * `regionName` names its wide tables apart from every other block's
 * ("Bottom line 1 table"), so no two scroll regions share a name.
 */
export interface SafeMarkdownProps {
  markdown: string;
  subsectionIds?: readonly string[];
  skipFirstHeading?: boolean;
  cite?: boolean;
  inline?: boolean;
  regionName?: string;
  /** Keep every backslash the text wrote (`parseMarkdown`'s `keepBackslashes`). */
  keepBackslashes?: boolean;
  className?: string;
}

export default function SafeMarkdown(props: SafeMarkdownProps) {
  return (
    <MarkdownBoundary markdown={props.markdown}>
      <MarkdownBody {...props} />
    </MarkdownBoundary>
  );
}

function RawText({ markdown }: { markdown: string }) {
  return (
    <pre className="max-h-[40rem] overflow-auto whitespace-pre-wrap break-all rounded border border-border-light bg-bg-deep px-3 py-2 font-mono text-xs leading-5 text-text-secondary">
      {markdown}
    </pre>
  );
}

class MarkdownBoundary extends Component<{ markdown: string; children: ReactNode }, { failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  /* A new text gets a fresh try. The boundary is not keyed by the text, so a
   * streamed answer growing a chunk at a time is not remounted for each one. */
  componentDidUpdate(prev: { markdown: string }) {
    if (this.state.failed && prev.markdown !== this.props.markdown) this.setState({ failed: false });
  }

  render() {
    return this.state.failed ? <RawText markdown={this.props.markdown} /> : this.props.children;
  }
}

function MarkdownBody({
  markdown,
  subsectionIds = [],
  skipFirstHeading = false,
  cite = false,
  inline = false,
  regionName,
  keepBackslashes = false,
  className = "space-y-3 text-sm leading-6 text-text-primary",
}: SafeMarkdownProps) {
  const tooLong = markdown.length > MAX_MARKDOWN_CHARS;
  const nodes = useMemo(
    () => (tooLong ? [] : parseMarkdown(markdown, { linkIds: !cite, keepBackslashes })),
    [markdown, tooLong, cite, keepBackslashes],
  );
  if (tooLong) return <RawText markdown={markdown} />;
  const first = nodes[0];
  const shown = skipFirstHeading && first?.t === "el" && /^h[1-6]$/.test(first.tag) ? nodes.slice(1) : nodes;
  const ids: IdCursor = { next: 0, tables: 0, list: subsectionIds, cite, regionName };
  const lone = inline && shown.length === 1 && shown[0].t === "el" && shown[0].tag === "p" ? shown[0] : null;
  if (lone && lone.t === "el") return <span className={className}>{renderNodes(lone.c, ids)}</span>;
  return <div className={className}>{renderNodes(shown, ids)}</div>;
}

type IdCursor = {
  next: number;
  tables: number;
  list: readonly string[];
  /** Draw text through `CitedProse`. */
  cite?: boolean;
  regionName?: string;
};

const HEADING_CLASS: Record<string, string> = {
  h1: "text-base font-semibold",
  h2: "text-base font-semibold",
  h3: "text-sm font-semibold pt-2",
  h4: "text-sm font-medium text-text-secondary",
  h5: "text-xs font-medium text-text-secondary",
  h6: "text-xs font-medium text-text-muted",
};

/** A Markdown heading one level down: the section's own title is the h2. */
const HEADING_TAG: Record<string, "h2" | "h3" | "h4" | "h5" | "h6"> = {
  h1: "h2",
  h2: "h3",
  h3: "h4",
  h4: "h5",
  h5: "h6",
  h6: "h6",
};

function renderNodes(nodes: readonly MdNode[], ids: IdCursor): ReactNode[] {
  return nodes.map((node, i) => renderNode(node, i, ids));
}

function renderNode(node: MdNode, key: number, ids: IdCursor): ReactNode {
  switch (node.t) {
    case "text":
      return ids.cite ? <CitedProse key={key} text={node.v} /> : <Fragment key={key}>{node.v}</Fragment>;
    case "br":
      return <br key={key} />;
    case "hr":
      return <hr key={key} className="border-border-light" />;
    case "code":
      return (
        <code key={key} className="rounded bg-bg-deep px-1 font-mono text-[0.85em] [overflow-wrap:anywhere]">
          {node.v}
        </code>
      );
    case "pre":
      return (
        <pre
          key={key}
          className="max-h-[32rem] overflow-auto whitespace-pre-wrap break-all rounded border border-border-light bg-bg-deep px-3 py-2 font-mono text-xs leading-5 text-text-secondary"
        >
          {node.v}
        </pre>
      );
    case "el":
      return renderElement(node, key, ids);
  }
}

function renderElement(node: Extract<MdNode, { t: "el" }>, key: number, ids: IdCursor): ReactNode {
  const children = renderNodes(node.c, ids);
  switch (node.tag) {
    case "h1":
    case "h2":
    case "h3":
    case "h4":
    case "h5":
    case "h6": {
      const Tag = HEADING_TAG[node.tag];
      const id = node.sub ? ids.list[ids.next++] : undefined;
      return (
        <Tag key={key} id={id} className={`${HEADING_CLASS[node.tag]} scroll-mt-16 text-text-primary`}>
          {children}
        </Tag>
      );
    }
    case "p":
      return (
        <p key={key} className="break-words">
          {children}
        </p>
      );
    case "blockquote":
      return (
        <blockquote key={key} className="space-y-2 border-l-4 border-status-orange bg-status-orange/5 px-3 py-2 text-text-secondary">
          {children}
        </blockquote>
      );
    case "ul":
      return (
        <ul key={key} className="list-disc space-y-1 pl-5">
          {children}
        </ul>
      );
    case "ol":
      return (
        <ol key={key} start={node.start} className="list-decimal space-y-1 pl-5">
          {children}
        </ol>
      );
    case "li":
      return (
        <li key={key} className="space-y-1 break-words">
          {children}
        </li>
      );
    case "table":
      return (
        <div
          key={key}
          {...scrollRegion(ids.regionName ? `${ids.regionName} ${++ids.tables}` : `Table ${++ids.tables}`)}
          className={`max-w-full overflow-x-auto rounded border border-border-light ${SCROLL_REGION_FOCUS}`}
        >
          <table className="w-full text-xs">{children}</table>
        </div>
      );
    case "thead":
      return (
        <thead key={key} className="bg-bg-deep">
          {children}
        </thead>
      );
    case "tbody":
      return <tbody key={key}>{children}</tbody>;
    case "tr":
      return (
        <tr key={key} className="border-b border-border-light align-top last:border-b-0">
          {children}
        </tr>
      );
    case "th":
      return (
        <th key={key} scope="col" className="px-2 py-1.5 text-left font-medium text-text-muted" style={{ textAlign: node.align ?? undefined }}>
          {children}
        </th>
      );
    case "td":
      return (
        <td key={key} className="max-w-[28rem] px-2 py-1.5 break-words [overflow-wrap:anywhere]" style={{ textAlign: node.align ?? undefined }}>
          {children}
        </td>
      );
    case "strong":
      return (
        <strong key={key} className="font-semibold">
          {children}
        </strong>
      );
    case "em":
      return <em key={key}>{children}</em>;
    case "s":
      return <del key={key}>{children}</del>;
    case "a":
      if (!node.href) return <Fragment key={key}>{children}</Fragment>;
      return node.href.startsWith("#") ? (
        <a key={key} href={node.href} className="text-accent-strong underline hover:no-underline">
          {children}
        </a>
      ) : (
        <a key={key} href={node.href} target="_blank" rel="noopener noreferrer nofollow" className="text-accent-strong underline hover:no-underline [overflow-wrap:anywhere]">
          {children}
        </a>
      );
    default:
      // Any other element markdown-it might open is drawn as its text.
      return <Fragment key={key}>{children}</Fragment>;
  }
}
