import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useParams: () => ({ id: "J1" }) }));

import type { EvidenceSection } from "@/types/malware-report";
import ArtifactTable from "../ArtifactTable";
import { headedTable } from "../tableColumns";
import {
  API_CAPABILITIES,
  ARTIFACT_IMPORTS,
  BATCH_DECOMPILE,
  FUNCTIONS_EXAMINED,
  STRINGS_SECTION,
} from "./storedRunShapes";

const draw = (section: EvidenceSection) =>
  renderToStaticMarkup(createElement(ArtifactTable, { section }));
const count = (html: string, needle: RegExp) => (html.match(needle) ?? []).length;
const headings = (html: string) =>
  [...html.matchAll(/<th[^>]*>([^<]*)<\/th>/g)].map((m) => m[1]);
const rowsOf = (html: string) =>
  [...html.matchAll(/<tr class="hover:bg-bg-hover">(.*?)<\/tr>/g)].map((m) => count(m[1], /<td/g));

describe("a section with rows and a note (T-341)", () => {
  const html = draw(STRINGS_SECTION);

  it("draws every row and the note beneath them", () => {
    expect(rowsOf(html)).toHaveLength(3);
    expect(html).toContain("18 more rows not shown here; the evidence endpoint carries every one under");
  });

  it("links each ledger id the note names, and only the id", () => {
    expect(html).toContain('href="/analysis/J1/evidence?evidence=ev_0005"');
    expect(html).toContain('href="/analysis/J1/evidence?evidence=ev_0098"');
    expect(html).not.toMatch(/evidence=18%20more/);
  });
});

describe("a list with a counting sentence (T-341)", () => {
  const html = draw(FUNCTIONS_EXAMINED);

  it("draws the items and the sentence", () => {
    for (const item of FUNCTIONS_EXAMINED.items) expect(html).toContain(item);
    expect(html).toContain("Function map: 51 functions visited (51 decompiled)");
  });
});

describe("a section of every shape at once (T-341)", () => {
  it("draws rows, items and text together", () => {
    const html = draw({
      ...STRINGS_SECTION,
      kind: "kv",
      columns: ["Field", "Value"],
      rows: [["format", "pe"]],
      items: ["first answer as a list"],
      text: "and a third as prose, ev_0007",
    });
    expect(html).toContain("pe");
    expect(html).toContain("first answer as a list");
    expect(html).toContain("and a third as prose, ");
    expect(html).toContain("evidence=ev_0007");
  });

  it("still draws a plain table, list and paragraph as before", () => {
    const table = draw({ ...STRINGS_SECTION, text: "" });
    expect(rowsOf(table)).toHaveLength(3);
    expect(table).not.toContain("<ul");

    const list = draw({ ...FUNCTIONS_EXAMINED, text: "" });
    expect(count(list, /<li/g)).toBe(3);
    expect(list).not.toContain("<table");

    const text = draw({ ...FUNCTIONS_EXAMINED, kind: "text", items: [] });
    expect(text).toContain("Function map:");
    expect(text).not.toContain("<ul");
  });

  it("draws no empty paragraph for a section with no text", () => {
    const empty = draw({ ...FUNCTIONS_EXAMINED, kind: "text", items: [], text: "" });
    expect(empty).not.toContain("<p");
    const list = draw({ ...FUNCTIONS_EXAMINED, text: "" });
    expect(list).not.toContain("<p");
  });

  it("says a table returned no rows only when it carries nothing else", () => {
    expect(draw({ ...STRINGS_SECTION, rows: [], text: "" })).toContain("The tool returned no rows.");
    expect(draw({ ...STRINGS_SECTION, rows: [] })).not.toContain("The tool returned no rows.");
  });
});

describe("cells beyond the declared columns (T-343)", () => {
  it("heads a positional cell by its position, guessing no name", () => {
    expect(headedTable(ARTIFACT_IMPORTS.columns, ARTIFACT_IMPORTS.rows).columns).toEqual([
      "Listed by",
      "Evidence",
      "Library",
      "Column 4",
    ]);
  });

  it("draws every cell of the merged imports under a heading", () => {
    const html = draw(ARTIFACT_IMPORTS);
    const heads = headings(html);
    expect(heads).toContain("Column 4");
    for (const width of rowsOf(html)) expect(width).toBe(heads.length);
    expect(html).toContain("VirtualAllocEx");
    expect(html).toContain("HttpSendRequestA");
  });

  it("pads a short row so its cells stay under their own headings", () => {
    const { rows } = headedTable(API_CAPABILITIES.columns, API_CAPABILITIES.rows);
    expect(rows.every((row) => row.length === 7)).toBe(true);
    expect(rows[2][0]).toBe("PeekNamedPipe");
    expect(rows[2][6]).toBe("");
  });

  it("heads a keyed row's cells by the keys the row uses", () => {
    const headed = headedTable(["api"], [{ api: "WinExec", category: "execution" }]);
    expect(headed.columns).toEqual(["api", "category"]);
    expect(headed.rows).toEqual([["WinExec", "execution"]]);
  });

  it("prints a missing cell as the console's dash, never as `undefined`", () => {
    const html = draw({
      ...ARTIFACT_IMPORTS,
      rows: [["dynamic", null as unknown as string, "KERNEL32.dll"]],
    });
    expect(html).not.toMatch(/>undefined</);
    expect(html).not.toMatch(/>null</);
  });
});

describe("a decompiler's listing in a key/value row (T-333)", () => {
  const html = draw(BATCH_DECOMPILE);

  it("keeps the listing's lines, so its types read as code", () => {
    expect(count(html, /whitespace-pre-wrap/g)).toBe(2);
    expect(html).toContain("undefined4 FUN_1360bc03074(void)");
  });

  it("draws no cell or heading as a bare `undefined`", () => {
    expect(html).not.toMatch(/>\s*undefined\s*</);
  });
});
