import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import StixGraphView, { Detail } from "../StixGraph";
import { readStixGraph } from "../stixGraph";

const MALWARE = "malware--1";
const TECHNIQUE = "attack-pattern--2";
const LONE = "url--3";

const bundle = {
  type: "bundle",
  id: "bundle--x",
  objects: [
    { type: "malware", id: MALWARE, name: "sample.exe", is_family: false },
    {
      type: "attack-pattern",
      id: TECHNIQUE,
      name: "Process Injection",
      external_references: [{ source_name: "mitre-attack", external_id: "T1055" }],
    },
    { type: "url", id: LONE, value: "http://example.test/a" },
    {
      type: "relationship",
      id: "relationship--4",
      relationship_type: "uses",
      source_ref: MALWARE,
      target_ref: TECHNIQUE,
      x_maljan_confidence: 0.9,
      x_maljan_evidence_refs: ["ev_0002"],
    },
    { type: "report", id: "report--5", name: "r", object_refs: [MALWARE] },
  ],
};

const count = (html: string, needle: RegExp) => (html.match(needle) ?? []).length;

describe("the drawn graph", () => {
  const html = renderToStaticMarkup(createElement(StixGraphView, { bundle, showGraph: true }));

  it("draws one focusable node per object a reader follows, the unrelated one included", () => {
    expect(count(html, /<g tabindex="0" role="button"/g)).toBe(3);
    expect(html).toContain('aria-label="url: http://example.test/a"');
  });

  it("labels the edge with the bundle's word and the confidence it states", () => {
    expect(html).toContain("uses · 0.90");
  });

  it("marks what a saved picture leaves out and the plain look it keeps", () => {
    expect(html).toContain('data-plain-style="fill: none; stroke: var(--border); stroke-width: 1.25"');
    expect(count(html, /data-export="omit"/g)).toBe(1);
  });

  it("paints with the console's tokens and no gradient", () => {
    expect(html).toContain("var(--status-red)");
    expect(html).not.toMatch(/Gradient/);
  });

  it("keeps the table in the page for a screen reader, with no hidden controls in it", () => {
    const hidden = html.slice(html.indexOf('class="sr-only"'));
    expect(hidden).toContain("Objects (3)");
    expect(hidden).toContain("Relationships (1)");
    expect(hidden).toContain("In the bundle, not drawn (1)");
    expect(hidden.split("<aside")[0]).not.toContain("<button");
    expect(hidden.split("<aside")[0]).toContain("ev_0002");
    expect(hidden.split("<aside")[0]).not.toContain("<a ");
  });
});

describe("the table view", () => {
  const html = renderToStaticMarkup(createElement(StixGraphView, { bundle, showGraph: false }));

  it("draws no graph and lists every row as a control", () => {
    expect(html).not.toContain("<svg viewBox");
    expect(html).not.toContain('class="sr-only"');
    expect(count(html, /<button type="button"/g)).toBe(4);
  });

  it("links an edge's ledger ids into the evidence view", () => {
    expect(html).toContain("evidence?evidence=ev_0002");
  });

  it("says a missing confidence is not stated, never a number", () => {
    const table = renderToStaticMarkup(
      createElement(StixGraphView, {
        bundle: {
          objects: [
            bundle.objects[0],
            bundle.objects[1],
            { ...bundle.objects[3], x_maljan_confidence: undefined },
          ],
        },
        showGraph: false,
      }),
    );
    expect(table).toContain("not stated");
    expect(table).not.toMatch(/0\.00|0\.50/);
  });
});

describe("the detail pane", () => {
  const HASH = "d41d8cd98f00b204e9800998ecf8427ea41d8cd98f00b204e9800998ecf8427";
  const FILE = "file--6";
  const DROPPED = {
    type: "bundle",
    id: "bundle--y",
    objects: [
      { type: "malware", id: MALWARE, name: "sample.exe", is_family: false },
      { type: "file", id: FILE, hashes: { "SHA-256": HASH } },
      {
        type: "relationship",
        id: "relationship--7",
        relationship_type: "drops",
        source_ref: MALWARE,
        target_ref: FILE,
      },
    ],
  };
  const graph = readStixGraph(DROPPED);

  it("wraps a long node label and its relationship buttons instead of letting a sha256 run past the pane", () => {
    const html = renderToStaticMarkup(
      createElement(Detail, { graph, selection: { kind: "node", id: FILE }, onSelect: () => {} }),
    );
    expect(html).toContain(HASH);
    // break-words (overflow-wrap: break-word) does not stop an unbroken run
    // like a hash from setting a flex/grid item's own preferred width, so the
    // label and the relationship buttons that can carry one need break-all.
    expect(html).toContain(`text-text-primary break-all">SHA-256 ${HASH}`);
    expect(html).toMatch(/class="text-left text-xs text-accent-strong hover:underline break-all"/);
  });

  it("wraps the edge heading's source and target names", () => {
    const html = renderToStaticMarkup(
      createElement(Detail, { graph, selection: { kind: "edge", key: "relationship--7" }, onSelect: () => {} }),
    );
    expect(html).toContain(HASH);
    expect(
      (html.match(/class="text-accent-strong hover:underline text-left break-all"/g) ?? []).length,
    ).toBe(2);
  });

  it("wraps the raw JSON block's long string values", () => {
    const html = renderToStaticMarkup(
      createElement(Detail, { graph, selection: { kind: "node", id: FILE }, onSelect: () => {} }),
    );
    const jsonBlock = html.slice(html.indexOf("<div class=\"p-3"));
    expect(jsonBlock).toContain("font-mono text-[11px] leading-relaxed break-all overflow-x-auto");
    expect(jsonBlock).toContain(HASH);
  });
});
