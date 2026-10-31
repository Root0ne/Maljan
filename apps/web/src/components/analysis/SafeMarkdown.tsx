"use client";

import { Component, Fragment, useMemo, type ReactNode } from "react";
import { scrollRegion, SCROLL_REGION_FOCUS } from "@/components/ui/scrollRegion";
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
 */
export default function SafeMarkdown(props: {
  markdown: string;
  subsectionIds?: readonly string[];
  skipFirstHeading?: boolean;
}) {
  return (
    <MarkdownBoundary key={props.markdown} markdown={props.markdown}>
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

  render() {
    return this.state.failed ? <RawText markdown={this.props.markdown} /> : this.props.children;
  }
}

function MarkdownBody({
  markdown,
  subsectionIds = [],
  skipFirstHeading = false,
}: {
  markdown: string;
  subsectionIds?: readonly string[];
  skipFirstHeading?: boolean;
}) {
  const tooLong = markdown.length > MAX_MARKDOWN_CHARS;
  const nodes = useMemo(() => (tooLong ? [] : parseMarkdown(markdown)), [markdown, tooLong]);
  if (tooLong) return <RawText markdown={markdown} />;
  const first = nodes[0];
  const shown = skipFirstHeading && first?.t === "el" && /^h[1-6]$/.test(first.tag) ? nodes.slice(1) : nodes;
  const ids = { next: 0, tables: 0, list: subsectionIds };
  return <div className="space-y-3 text-sm leading-6 text-text-primary">{renderNodes(shown, ids)}</div>;
}

type IdCursor = { next: number; tables: number; list: readonly string[] };

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
      return <Fragment key={key}>{node.v}</Fragment>;
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
        <Tag key={key} id={id} className={`${HEADING_CLASS[node.tag]} scroll-mt-40 text-text-primary`}>
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
          {...scrollRegion(`Table ${++ids.tables}`)}
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
