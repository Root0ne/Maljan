/** An unread upload's proposed format declaration, as the console reads and draws it. */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import ReportFormatProposal from "../ReportFormatProposal";
import {
  isUnread,
  parseDeclaration,
  readProposal,
  shownFields,
  showValue,
} from "../reportFormatProposal";

const PROPOSAL = {
  v: 1,
  fields: {
    "mapping.processes": {
      value: "$['process_list'][*]",
      evidence: ["report.process_list[] (parent_process_id, process_id, process_name)"],
      confidence: "medium",
    },
    detect: {
      value: [[{ path: "/process_list", types: ["array"] }]],
      evidence: ["report.process_list (array)"],
      confidence: "medium",
    },
    reader: { value: "generic", evidence: ["no format recognises it"], confidence: "high" },
    "mapping.field_names.processes.pid": {
      value: "process_id",
      evidence: ["report.process_list[].process_id"],
      confidence: "medium",
      requires: ["mapping.processes"],
    },
  },
  declaration: {
    name: "sandbox_361107b0",
    detect: [[{ path: "/process_list", types: ["array"] }]],
    reader: "generic",
    mapping: { processes: "$['process_list'][*]" },
  },
};

describe("readProposal", () => {
  it("keeps a well-formed proposal and its declaration", () => {
    const read = readProposal(PROPOSAL);
    expect(read?.declaration?.name).toBe("sandbox_361107b0");
    expect(Object.keys(read?.fields ?? {})).toHaveLength(4);
    expect(read?.fields["mapping.field_names.processes.pid"].requires).toEqual([
      "mapping.processes",
    ]);
  });

  it("drops a field of an odd shape and refuses a proposal of none", () => {
    const read = readProposal({
      v: 1,
      fields: { a: { value: 1, evidence: ["x"], confidence: "certain" }, b: "nope" },
    });
    expect(read?.fields).toEqual({});
    expect(readProposal(null)).toBeNull();
    expect(readProposal({ fields: {} })).toBeNull();
  });

  it("keeps the reason no declaration could be made", () => {
    expect(readProposal({ v: 1, fields: {}, failed: "no block" })?.failed).toBe("no block");
  });
});

describe("shownFields", () => {
  it("shows how the report is recognised first, then where its parts sit", () => {
    const names = shownFields(readProposal(PROPOSAL)!).map(([name]) => name);
    expect(names).toEqual([
      "detect",
      "reader",
      "mapping.field_names.processes.pid",
      "mapping.processes",
    ]);
  });
});

describe("parseDeclaration", () => {
  it("reads an edited declaration back", () => {
    const read = parseDeclaration('{"name": "acme_flat", "reader": "generic"}');
    expect(read.ok && read.value.name).toBe("acme_flat");
  });

  it("refuses text that is no declaration, in words", () => {
    expect(parseDeclaration("{").ok).toBe(false);
    expect(parseDeclaration("[]").ok).toBe(false);
    expect(parseDeclaration('{"reader": "generic"}').ok).toBe(false);
  });
});

describe("ReportFormatProposal", () => {
  it("draws each field with its confidence and evidence, as text", () => {
    const hostile = {
      ...PROPOSAL,
      fields: {
        ...PROPOSAL.fields,
        "mapping.channels.x": {
          value: "<img src=x onerror=alert(1)>",
          evidence: ["<script>bad()</script>"],
          confidence: "low",
        },
      },
    };
    const html = renderToStaticMarkup(
      createElement(ReportFormatProposal, {
        proposal: readProposal(hostile)!,
        busy: false,
        error: null,
        canAccept: true,
        onAccept: () => {},
      })
    );
    expect(html).toContain("medium confidence");
    expect(html).toContain("Accept this declaration");
    expect(html).toContain("sandbox_361107b0");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<script>");
    expect(html).toContain("&lt;img");
  });

  it("offers no accept where no declaration could be made", () => {
    const html = renderToStaticMarkup(
      createElement(ReportFormatProposal, {
        proposal: readProposal({ v: 1, fields: {}, failed: "no block is named plainly" })!,
        busy: false,
        error: null,
        canAccept: true,
        onAccept: () => {},
      })
    );
    expect(html).toContain("no block is named plainly");
    expect(html).not.toContain("Accept this declaration");
  });

  it("offers the accept to an admin alone", () => {
    const html = renderToStaticMarkup(
      createElement(ReportFormatProposal, {
        proposal: readProposal(PROPOSAL)!,
        busy: false,
        error: null,
        canAccept: false,
        onAccept: () => {},
      })
    );
    expect(html).not.toContain("Accept this declaration");
    expect(html).not.toContain("<textarea");
    expect(html).toContain("An admin accepts or edits this declaration.");
    expect(html).toContain("mapping.processes");
  });

  it("says, as text, what the reading horizons left unread", () => {
    const read = readProposal({
      ...PROPOSAL,
      notes: ["3 containers nested more than 16 path segments <b>x</b>", 7],
    })!;
    expect(read.notes).toEqual(["3 containers nested more than 16 path segments <b>x</b>"]);
    const html = renderToStaticMarkup(
      createElement(ReportFormatProposal, {
        proposal: read,
        busy: false,
        error: null,
        canAccept: true,
        onAccept: () => {},
      })
    );
    expect(html).toContain("16 path segments &lt;b&gt;x&lt;/b&gt;");
  });

  it("knows an unread row by its format", () => {
    expect(isUnread("unread")).toBe(true);
    expect(isUnread("cape2")).toBe(false);
    expect(isUnread(null)).toBe(false);
  });

  it("shows a value as one line", () => {
    expect(showValue("x")).toBe("x");
    expect(showValue([1, { a: 2 }])).toBe('[1,{"a":2}]');
  });
});
