import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import served from "@/test-fixtures/settings-schema.json";
import type { McpServerEntry, SettingsSchema, ToolDeclarationFields } from "@/types/settings";
import DeclarationFields, { ToolFactsBox, trustWithdrawn } from "../DeclarationFields";
import { keptAsStored, readToolFacts } from "../declarationFields";

const FIELDS = (served as unknown as SettingsSchema).tool_declaration_fields as ToolDeclarationFields;

/* A stored change naming no kind of its own: laid by the API over the kind
 * the server's listing declares (`tool_declarations.kind_free_changes`). */
const RANKED = { reputation: { rank: 30 } };
const HELD = { lookup: RANKED };

describe("a stored change the field rules refuse in an edit", () => {
  it("is kept while left as it is, so the other tools can be edited around it", () => {
    const text = JSON.stringify({ lookup: RANKED, scan: { kind: "strings" } });
    expect(readToolFacts(text, "", FIELDS, HELD)).toEqual({
      value: { lookup: RANKED, scan: { kind: "strings" } },
      error: null,
    });
    // Its keys in another order are the same declaration.
    expect(readToolFacts('{"lookup": {"reputation": {"rank": 30}}}', "", FIELDS, HELD).error).toBeNull();
  });

  it("is checked in full once edited, and a new one is refused as ever", () => {
    const changed = JSON.stringify({ lookup: { reputation: { rank: 31 } } });
    expect(readToolFacts(changed, "", FIELDS, HELD).error).toMatch(/read only through a kind/);
    const added = JSON.stringify({ lookup: RANKED, other: RANKED });
    expect(readToolFacts(added, "", FIELDS, HELD).error).toMatch(/^other: .*read only through a kind/);
    expect(readToolFacts(JSON.stringify(HELD), "", FIELDS).error).toMatch(/read only through a kind/);
  });

  it("is named apart from the box", () => {
    expect(keptAsStored({ ...HELD, scan: { kind: "strings" } }, "", FIELDS)).toEqual(["lookup"]);
    expect(keptAsStored({ scan: { kind: "strings" } }, "", FIELDS)).toEqual([]);
    const html = renderToStaticMarkup(
      createElement(ToolFactsBox, {
        id: "mine.tool_facts",
        ariaLabel: "mine tool_facts",
        serverKey: "mine",
        shipped: {},
        changes: { "": "changes", ...HELD },
        fields: FIELDS,
        onChanges: () => {},
      })
    );
    expect(html).toContain('data-tool-facts-kept="mine"');
    expect(html).toContain("Kept as stored while left as they are: lookup.");
  });
});

/* A block as the API serves it: trusting, with the launch its trust holds for. */
const SAVED: McpServerEntry = {
  enabled: true,
  transport: "stdio",
  command: "/usr/bin/mine-mcp",
  args: [],
  trusts_served_declaration: true,
  trust_granted_for: "0123456789abcdef",
} as unknown as McpServerEntry;

function box(server: McpServerEntry, saved: McpServerEntry | undefined) {
  return renderToStaticMarkup(
    createElement(DeclarationFields, { serverKey: "mine", server, saved, put: () => {} })
  );
}

const checkedBox = /aria-label="mine trusts_served_declaration"[^>]*checked=""/;

describe("the trust in a server's own declaration, as the box shows it", () => {
  it("shows the trust a block holds where it still points", () => {
    expect(trustWithdrawn(SAVED, SAVED)).toBe(false);
    expect(box(SAVED, SAVED)).toMatch(checkedBox);
  });

  it("shows it off, and says why, once the block is pointed elsewhere", () => {
    for (const moved of [
      { ...SAVED, command: "/usr/bin/other-mcp" },
      { ...SAVED, args: ["--other"] },
      { ...SAVED, transport: "streamable-http", url: "https://mcp.example.invalid/mcp" },
    ] as McpServerEntry[]) {
      expect(trustWithdrawn(moved, SAVED)).toBe(true);
      const html = box(moved, SAVED);
      expect(html).not.toMatch(checkedBox);
      expect(html).toContain('data-trust-withdrawn="mine"');
    }
  });

  it("shows the shipped value posted back by a moved block off too", () => {
    const shipped = { ...SAVED, trust_granted_for: undefined };
    expect(trustWithdrawn({ ...shipped, command: "/usr/bin/other-mcp" }, shipped)).toBe(true);
  });

  it("shows an operator's tick on, wherever the block points", () => {
    const ticked = { ...SAVED, command: "/usr/bin/other-mcp", trust_granted_for: "" };
    expect(trustWithdrawn(ticked, SAVED)).toBe(false);
    expect(box(ticked, SAVED)).toMatch(checkedBox);
    expect(box(ticked, SAVED)).not.toContain("data-trust-withdrawn");
  });

  it("reads a server not saved yet by its own flag", () => {
    expect(trustWithdrawn(SAVED, undefined)).toBe(false);
    const off = { ...SAVED, trusts_served_declaration: false };
    expect(trustWithdrawn({ ...off, command: "/x" }, SAVED)).toBe(false);
  });
});
