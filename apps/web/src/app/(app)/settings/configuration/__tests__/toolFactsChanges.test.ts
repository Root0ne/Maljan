import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import served from "@/test-fixtures/settings-schema.json";
import type { CatalogEntry, SettingsSchema, ToolDeclarationFields } from "@/types/settings";
import { ToolFactsBox } from "../DeclarationFields";
import ToolFactsLeafEditor from "../ToolFactsLeafEditor";
import {
  changedTools,
  mergeToolFacts,
  resetTool,
  toolFactsChanges,
} from "../toolFactsChanges";

const FIELDS = (served as unknown as SettingsSchema).tool_declaration_fields as ToolDeclarationFields;

/* What a built-in ships, as the server map's default holds it (full dumps). */
const SHIPPED = {
  scan: { kind: "rule_match", rows: "/hits/*", timeout_seconds: null, long_running: false },
  list: { kind: "strings", rows: "", timeout_seconds: null, long_running: false },
  peek: { kind: "strings", rows: "", timeout_seconds: 30, long_running: false },
};

describe("a block's tool declarations as stored, per tool", () => {
  it("merges the shipped map with the stored changes field by field", () => {
    const changes = { scan: { long_running: true }, list: null, mine: { kind: "decompile" } };
    const inForce = mergeToolFacts(SHIPPED, changes);
    expect(Object.keys(inForce)).toEqual(["scan", "peek", "mine"]);
    expect(inForce.scan).toEqual({ ...SHIPPED.scan, long_running: true });
    expect(inForce.peek).toBe(SHIPPED.peek);
    expect(inForce.mine).toEqual({ kind: "decompile" });
  });

  it("stages only what an edit changes of the shipped declarations", () => {
    const edited = mergeToolFacts(SHIPPED, undefined) as Record<string, Record<string, unknown>>;
    expect(toolFactsChanges(edited, SHIPPED, FIELDS)).toEqual({});
    const next: Record<string, unknown> = {
      scan: { ...edited.scan, timeout_seconds: 600 },
      peek: edited.peek,
      pack_scan: { display_name: "Pack scanner" },
    };
    expect(toolFactsChanges(next, SHIPPED, FIELDS)).toEqual({
      scan: { timeout_seconds: 600 },
      list: null,
      pack_scan: { display_name: "Pack scanner" },
    });
  });

  it("reads a field an edit deletes from a shipped tool as its default", () => {
    const next = { ...SHIPPED, peek: { kind: "strings", rows: "", long_running: false } };
    expect(toolFactsChanges(next, SHIPPED, FIELDS)).toEqual({ peek: { timeout_seconds: null } });
    // Without the served split the default is unknown, and the shipped value stays.
    expect(toolFactsChanges(next, SHIPPED, null)).toEqual({});
  });

  it("is the whole map for a server that ships nothing", () => {
    const own = { scan: { kind: "rule_match", rows: "/hits/*" } };
    expect(toolFactsChanges(own, {}, FIELDS)).toEqual(own);
    expect(mergeToolFacts({}, own)).toEqual(own);
  });

  it("lists each tool that carries a change, and resets one to shipped", () => {
    const changes = {
      scan: { long_running: true },
      list: null,
      peek: { timeout_seconds: 30 },
      mine: { kind: "decompile" },
    };
    expect(changedTools(SHIPPED, changes)).toEqual([
      { tool: "scan", state: "changed" },
      { tool: "list", state: "removed" },
      { tool: "mine", state: "added" },
    ]);
    expect(resetTool(changes, "list")).toEqual({
      scan: { long_running: true },
      peek: { timeout_seconds: 30 },
      mine: { kind: "decompile" },
    });
    // A full dump equal to shipped (a value served before any save) is no change.
    expect(changedTools(SHIPPED, { ...SHIPPED })).toEqual([]);
  });
});

describe("the tool declarations box", () => {
  const render = (shipped: Record<string, Record<string, unknown>>, changes?: unknown) =>
    renderToStaticMarkup(
      createElement(ToolFactsBox, {
        id: "b",
        ariaLabel: "s tool_facts",
        serverKey: "s",
        shipped,
        changes: changes as never,
        fields: FIELDS,
        onChanges: () => {},
      })
    );

  it("shows what is in force and names each changed tool with a reset", () => {
    const html = render(SHIPPED, { scan: { long_running: true }, list: null });
    expect(html).toContain("in force");
    expect(html).toContain('data-tool-change="changed"');
    expect(html).toContain('data-tool-change="removed"');
    expect(html).toContain("reset scan to shipped");
    expect(html).toContain("reset list to shipped");
    expect(html).toContain("&quot;peek&quot;");
    expect(html).not.toContain("&quot;list&quot;");
  });

  it("says every tool is as shipped when nothing is changed", () => {
    expect(render(SHIPPED)).toContain("Every tool is as shipped.");
  });

  it("lists nothing for a server that ships nothing", () => {
    const html = render({}, { mine: { kind: "strings" } });
    expect(html).not.toContain("data-tool-changes");
    expect(html).not.toContain("in force");
  });

  it("edits a provider block's leaf against the catalog default", () => {
    const entry = {
      key: "core.static.x.tool_facts",
      title: "X tool declarations",
      default: SHIPPED,
      editor: "tool_facts",
    } as unknown as CatalogEntry;
    const html = renderToStaticMarkup(
      createElement(ToolFactsLeafEditor, {
        entry,
        current: { value: { peek: null }, source: "ui" } as never,
        staged: undefined,
        onChange: () => {},
      })
    );
    expect(html).toContain('data-tool-change="removed"');
    expect(html).toContain("reset peek to shipped");
    const unsaved = renderToStaticMarkup(
      createElement(ToolFactsLeafEditor, {
        entry,
        current: { value: SHIPPED, source: "default" } as never,
        staged: undefined,
        onChange: () => {},
      })
    );
    expect(unsaved).toContain("Every tool is as shipped.");
  });
});
