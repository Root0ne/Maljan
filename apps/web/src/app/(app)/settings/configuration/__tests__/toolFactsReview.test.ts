import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import served from "@/test-fixtures/settings-schema.json";
import type { CatalogEntry, SettingsSchema, ToolDeclarationFields } from "@/types/settings";
import { ToolFactsBox } from "../DeclarationFields";
import { describeChange } from "../describeChange";
import { buildImportPreview } from "../importPreview";
import { buildReviewItems } from "../ReviewList";
import { mergeToolFacts, resetTool, toolFactsChanges } from "../toolFactsChanges";

/* The review list and the import preview compare a block's tool declarations
 * per tool, as they are in force: only the tools that change, are removed,
 * are added or are reset to shipped are named; never the mark, never a
 * shipped tool that did not change. */

const MARK = { "": "changes" } as const;
const FIELDS = (served as unknown as SettingsSchema).tool_declaration_fields as ToolDeclarationFields;

/* A provider block shipping many tools, as the catalog default holds them. */
const SHIPPED: Record<string, Record<string, unknown>> = Object.fromEntries(
  Array.from({ length: 165 }, (_, i) => [
    `tool_${String(i).padStart(3, "0")}`,
    { kind: "strings", rows: "", timeout_seconds: 30, long_running: false, display_name: "" },
  ])
);
const FIRST = "tool_000";
const SECOND = "tool_001";

const LEAF = {
  key: "core.static.block.tool_facts",
  namespace: "core",
  path: "static.block.tool_facts",
  type: "json",
  default: SHIPPED,
  nullable: false,
  choices: null,
  minimum: null,
  maximum: null,
  secret: false,
  group: "block",
  title: "Block tool declarations",
  description: "",
  applies: "next_job",
  editable: true,
  reason: null,
  probe: null,
  applies_when: null,
  order: 0,
  choices_from: null,
  editor: "tool_facts",
  subgroup: null,
  advanced: false,
  required_env: null,
} as unknown as CatalogEntry;

function edited(tool: string, fields: Record<string, unknown>) {
  const inForce = { ...mergeToolFacts(SHIPPED, undefined), [tool]: { ...SHIPPED[tool], ...fields } };
  return toolFactsChanges(inForce, SHIPPED, FIELDS);
}

describe("the review line of a block's tool declarations", () => {
  it("names one tool on a first save that changes one field", () => {
    // A leaf with no stored row is served with what ships, whole.
    const line = describeChange(LEAF, SHIPPED, edited(FIRST, { timeout_seconds: 1234 }), FIELDS);
    expect(line.summary).toBe("1 tool changed");
    expect(line.detail).toEqual([`${FIRST}: changed: timeout_seconds 30 → 1234`]);
  });

  it("never names the mark", () => {
    const line = describeChange(LEAF, SHIPPED, edited(FIRST, { long_running: true }), FIELDS);
    for (const text of [line.summary, ...(line.detail ?? [])]) {
      expect(text).not.toMatch(/(^|\s)(: )?changes$/);
      expect(text).not.toContain("+ :");
    }
    expect(line.detail).toHaveLength(1);
  });

  it("reads a reset to shipped as a reset", () => {
    const before = { ...MARK, [FIRST]: { timeout_seconds: 5 }, [SECOND]: null };
    const firstBack = describeChange(LEAF, before, resetTool(before, FIRST), FIELDS);
    expect(firstBack.summary).toBe("1 tool reset to shipped");
    expect(firstBack.detail).toEqual([`${FIRST}: reset to shipped`]);
    const secondBack = describeChange(LEAF, before, resetTool(before, SECOND), FIELDS);
    expect(secondBack.detail).toEqual([`${SECOND}: reset to shipped`]);
  });

  it("names a removed tool and an added one", () => {
    const after = { ...MARK, [SECOND]: null, mine: { kind: "strings", display_name: "Mine" } };
    const line = describeChange(LEAF, { ...MARK }, after, FIELDS);
    expect(line.summary).toBe("1 tool removed, 1 tool added");
    expect(line.detail).toEqual([`${SECOND}: removed`, "mine: added"]);
  });

  it("names nothing when the forms differ but nothing in force does", () => {
    const line = describeChange(LEAF, SHIPPED, { ...MARK }, FIELDS);
    expect(line.summary).toBe("no tool changes");
    expect(line.detail).toBeUndefined();
  });

  it("is what the review list shows for a staged leaf", () => {
    const schema = { groups: [{ key: "block", title: "Block", description: "", entries: [LEAF] }] };
    const items = buildReviewItems({
      schema: schema as unknown as SettingsSchema,
      pending: { [LEAF.key]: edited(FIRST, { timeout_seconds: 1234 }) },
      entriesByKey: { [LEAF.key]: LEAF },
      values: {
        [LEAF.key]: {
          value: SHIPPED,
          is_set: false,
          hint: null,
          source: "default",
          updated_at: null,
          updated_by: null,
        },
      },
      hiddenKeys: [],
      errors: {},
    });
    expect(items).toHaveLength(1);
    expect(items[0].detail).toEqual([`${FIRST}: changed: timeout_seconds 30 → 1234`]);
  });
});

describe("the import preview of a block's tool declarations", () => {
  const entries = { [LEAF.key]: LEAF };

  it("names only the tool a /2 file changes over an unstored leaf", () => {
    const preview = buildImportPreview(
      { format: "maljan-settings/2", values: { [LEAF.key]: { ...MARK, [FIRST]: { timeout_seconds: 5 } } } },
      entries,
      { [LEAF.key]: SHIPPED },
      FIELDS
    );
    expect(preview.lines).toHaveLength(1);
    expect(preview.lines[0].detail).toEqual([`${FIRST}: changed: timeout_seconds 30 → 5`]);
  });

  it("reads a map without the mark whole, as the API does", () => {
    const whole = { ...SHIPPED };
    delete whole[SECOND];
    const preview = buildImportPreview(
      { format: "maljan-settings/1", values: { [LEAF.key]: whole } },
      entries,
      { [LEAF.key]: { ...MARK } },
      FIELDS
    );
    expect(preview.lines[0].detail).toEqual([`${SECOND}: removed`]);
  });

  it("leaves out a file whose declarations put in force what is in force now", () => {
    const preview = buildImportPreview(
      { format: "maljan-settings/1", values: { [LEAF.key]: SHIPPED } },
      entries,
      { [LEAF.key]: { ...MARK } },
      FIELDS
    );
    expect(preview.lines).toEqual([]);
  });
});

describe("a conflicting change of a tool the block does not ship", () => {
  it("is marked and offers a reset that removes the stored change", () => {
    const changes = { ...MARK, gone: { kind: "strings", places: { offset: "/o" } } };
    const html = renderToStaticMarkup(
      createElement(ToolFactsBox, {
        id: "b",
        ariaLabel: "s tool_facts",
        serverKey: "s",
        shipped: { [FIRST]: SHIPPED[FIRST] },
        changes,
        fields: FIELDS,
        conflicts: ["gone"],
        onChanges: () => {},
      })
    );
    expect(html).toContain('data-tool-conflict="gone"');
    expect(html).toMatch(/aria-label="reset gone to shipped"[^>]*>Reset</);
    expect(resetTool(changes, "gone")).toEqual({ ...MARK });
  });
});

/* The server map, whose entries hold a built-in server's tool declarations
 * stored as their changes over what it ships. */
const SERVER_MAP = {
  ...LEAF,
  key: "core.mcp.servers",
  path: "mcp.servers",
  title: "Tool servers",
  editor: "server_map",
  builtin_servers: ["srv"],
  default: { srv: { transport: "http", url: "http://127.0.0.1:9/mcp", tool_facts: SHIPPED } },
} as unknown as CatalogEntry;

describe("the import preview of a server's tool declarations", () => {
  const entries = { [SERVER_MAP.key]: SERVER_MAP };
  const server = (tool_facts: unknown) => ({
    srv: { transport: "http", url: "http://127.0.0.1:9/mcp", tool_facts },
  });

  it("leaves out a /1 file whose whole map puts in force what is in force now", () => {
    const stored = { ...MARK, [FIRST]: { timeout_seconds: 5 } };
    const whole = mergeToolFacts(SHIPPED, stored);
    const preview = buildImportPreview(
      { format: "maljan-settings/1", values: { [SERVER_MAP.key]: server(whole) } },
      entries,
      { [SERVER_MAP.key]: server(stored) },
      FIELDS
    );
    expect(preview.lines).toEqual([]);
  });

  it("still names a server whose tool declarations change in force", () => {
    const whole = { ...SHIPPED };
    delete whole[SECOND];
    const preview = buildImportPreview(
      { format: "maljan-settings/1", values: { [SERVER_MAP.key]: server(whole) } },
      entries,
      { [SERVER_MAP.key]: server({ ...MARK }) },
      FIELDS
    );
    expect(preview.lines).toHaveLength(1);
    expect(preview.lines[0].detail).toEqual([
      "srv: changed: tool_facts",
      `srv: tool ${SECOND}: removed`,
    ]);
  });

  it("names each tool that changes in force, and how", () => {
    const sent = server({ ...MARK, [FIRST]: { timeout_seconds: 7 }, zz_new: { kind: "strings" } });
    const preview = buildImportPreview(
      { format: "maljan-settings/2", values: { [SERVER_MAP.key]: sent } },
      entries,
      { [SERVER_MAP.key]: server({ ...MARK }) },
      FIELDS
    );
    const detail = preview.lines[0].detail ?? [];
    expect(detail[0]).toBe("srv: changed: tool_facts");
    expect(detail).toContain("srv: tool zz_new: added");
    expect(detail.some((line) => line.startsWith(`srv: tool ${FIRST}: changed: timeout_seconds`))).toBe(true);
    expect(detail).toHaveLength(3);
  });

  it("still names a server whose other field changes beside equal declarations", () => {
    const stored = server({ ...MARK });
    const sent = { srv: { ...stored.srv, call_timeout_seconds: 9, tool_facts: SHIPPED } };
    const preview = buildImportPreview(
      { format: "maljan-settings/1", values: { [SERVER_MAP.key]: sent } },
      entries,
      { [SERVER_MAP.key]: stored },
      FIELDS
    );
    expect(preview.lines[0].detail).toEqual(["srv: changed: call_timeout_seconds"]);
  });
});

describe("an empty value and an empty name", () => {
  it("shows an empty value before the arrow", () => {
    const line = describeChange(LEAF, SHIPPED, edited(FIRST, { display_name: "Z" }), FIELDS);
    expect(line.detail).toEqual([`${FIRST}: changed: display_name "" → Z`]);
  });

  it("says the stored map as a whole is not in force when the API lists the mark's key", () => {
    const html = renderToStaticMarkup(
      createElement(ToolFactsBox, {
        id: "b",
        ariaLabel: "s tool_facts",
        serverKey: "s",
        shipped: { [FIRST]: SHIPPED[FIRST] },
        changes: { ...MARK },
        fields: FIELDS,
        conflicts: [""],
        onChanges: () => {},
      })
    );
    expect(html).toContain('data-tool-conflicts-unlisted="s"');
    expect(html).toContain("form no release writes");
  });

  it("shows a conflicting name no row carries, an empty one visibly", () => {
    const html = renderToStaticMarkup(
      createElement(ToolFactsBox, {
        id: "b",
        ariaLabel: "s tool_facts",
        serverKey: "s",
        shipped: {},
        changes: { ...MARK },
        fields: FIELDS,
        conflicts: ["mine__scan"],
        onChanges: () => {},
      })
    );
    expect(html).toContain("Stored changes not in force: mine__scan");
  });
});

describe("a tool named like a prototype key", () => {
  // JSON.parse keeps `__proto__` an own key, as the API serves it.
  const proto = JSON.parse('{"__proto__": {"kind": "strings", "display_name": "P"}}');

  it("is named by the review line when it is added", () => {
    const line = describeChange(LEAF, { ...MARK }, { ...MARK, ...proto }, FIELDS);
    expect(line.summary).toBe("1 tool added");
    expect(line.detail).toEqual(["__proto__: added"]);
  });

  it("is named by the review line when it is removed", () => {
    const before = toolFactsChanges(mergeToolFacts(SHIPPED, { ...MARK, ...proto }), SHIPPED, FIELDS);
    const line = describeChange(LEAF, before, resetTool(before, "__proto__"), FIELDS);
    expect(line.detail).toEqual(["__proto__: removed"]);
  });
});
