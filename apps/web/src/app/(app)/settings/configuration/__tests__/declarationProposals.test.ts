/**
 * The declarations a probe proposes, and what accepting one stages.
 *
 * Accepting stages the field in the server's declaration, with only the
 * fields it needs to validate and never a kind it did not ask for; nothing is
 * staged before an accept and nothing is called before a confirm. The
 * proposal is the server's data and is shown as text.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import served from "@/test-fixtures/settings-schema.json";
import type { McpServerEntry, ProbeResult, SettingsSchema, ToolDeclarationFields } from "@/types/settings";
import { readToolFacts } from "../declarationFields";
import { mergeToolFacts } from "../toolFactsChanges";
import DeclarationProposals from "../DeclarationProposals";
import {
  acceptField,
  acceptServerField,
  acceptTool,
  alsoStaged,
  isAccepted,
  readProposals,
  withRequired,
  type Proposals,
  type ToolProposal,
} from "../declarationProposals";

/* The mark a map of changes carries, as the API stores and serves it. */
const MARK = { "": "changes" } as const;

const SERVER: McpServerEntry = {
  enabled: true,
  transport: "stdio",
  command: "invented-server",
  args: [],
  env: {},
  cwd: "",
  env_allow: [],
  url: "",
  auth_token: "",
  auth_token_source: "default",
  tools: [],
  agents: [],
  label: "",
};

const SCAN: ToolProposal = {
  facts: {
    kind: "signature_rules",
    rows: "/matches/*",
    places: { offset: "/strings/*/offset" },
    techniques: [{ path: "/**2/tags", format: "sigma_tag" }],
    asserts_techniques: true,
    display_name: "Rule scanner",
  },
  fields: {
    kind: { value: "signature_rules", evidence: ["description (rule match)"], confidence: "low" },
    rows: {
      value: "/matches/*",
      evidence: ["outputSchema.matches (a list of objects)"],
      confidence: "medium",
      requires: ["kind"],
    },
    places: {
      value: { offset: "/strings/*/offset" },
      evidence: ["outputSchema.matches[].strings[].offset"],
      confidence: "medium",
      requires: ["kind", "rows"],
    },
    techniques: {
      value: [{ path: "/**2/tags", format: "sigma_tag" }],
      evidence: ["outputSchema.matches[].tags"],
      confidence: "medium",
      requires: ["kind"],
    },
    asserts_techniques: {
      value: true,
      evidence: ["rows with techniques"],
      confidence: "low",
      requires: ["kind", "techniques"],
    },
    display_name: { value: "Rule scanner", evidence: ["title"], confidence: "high" },
  },
};

const LISTER: ToolProposal = {
  facts: { display_name: "Sections", arguments: { path: "path" } },
  fields: {
    display_name: { value: "Sections", evidence: ["title"], confidence: "high" },
    arguments: { value: { path: "path" }, evidence: ["inputSchema.properties.path (name)"], confidence: "high" },
  },
};

function result(proposals: unknown): ProbeResult {
  return { ok: true, latency_ms: 1, detail: "", models: null, tools: ["scan"], details: { proposals } };
}

function render(proposals: Proposals, over: Record<string, unknown> = {}): string {
  return renderToStaticMarkup(
    createElement(DeclarationProposals, {
      serverKey: "s",
      server: SERVER,
      proposals,
      put: () => {},
      ...over,
    }),
  );
}

describe("readProposals", () => {
  it("reads a probe's proposals and leaves out a part of an odd shape", () => {
    const read = readProposals(
      result({
        v: 1,
        tools: {
          scan: SCAN,
          lister: LISTER,
          bad: { facts: { kind: 3 } },
          odd: "x",
          half: { facts: {}, fields: { kind: 5, rows: { value: "/r", confidence: "sure" } } },
        },
        server: { error_patterns: { value: [{ match: "x" }], evidence: ["e"], confidence: "medium" } },
        probed: { scan: "called", other: 4 },
        planned: [
          {
            tool: "lister",
            arguments: { path: "/nonexistent-maljan-probe/x" },
            remote: false,
            credential: false,
            withheld: ["auth token"],
          },
          { tool: 5, arguments: {} },
        ],
        failed: { deep: "no proposal: reading its schema raised RecursionError", odd: 1 },
      }),
    );
    expect(read).not.toBeNull();
    expect(Object.keys(read!.tools)).toEqual(["scan", "lister", "half"]);
    expect(read!.tools.half.fields).toEqual({ rows: { value: "/r", evidence: [], confidence: "low" } });
    expect(read!.server.error_patterns.confidence).toBe("medium");
    expect(read!.probed).toEqual({ scan: "called" });
    expect(read!.planned).toEqual([
      {
        tool: "lister",
        arguments: { path: "/nonexistent-maljan-probe/x" },
        remote: false,
        credential: false,
        withheld: ["auth token"],
      },
    ]);
    expect(read!.failed).toEqual({ deep: "no proposal: reading its schema raised RecursionError" });
  });

  it("keeps a tool named like a prototype key as its own proposal", () => {
    // JSON.parse keeps `__proto__` an own key, as the probe serves it.
    const raw = JSON.parse(
      `{"v": 1, "tools": {"__proto__": ${JSON.stringify(SCAN)}}, "probed": {"__proto__": "called"}}`,
    );
    const read = readProposals(result(raw));
    expect(Object.keys(read!.tools)).toEqual(["__proto__"]);
    expect(Object.prototype.hasOwnProperty.call(read!.tools, "__proto__")).toBe(true);
    expect(Object.keys(read!.probed ?? {})).toEqual(["__proto__"]);
  });

  it("is null for a result without proposals", () => {
    expect(readProposals(null)).toBeNull();
    expect(readProposals(result(undefined))).toBeNull();
    expect(readProposals(result({ tools: [] }))).toBeNull();
  });
});

describe("accepting", () => {
  it("stages a field read only through a kind together with that kind, and a kind-free one alone", () => {
    expect(withRequired(SCAN, "places")).toEqual(["kind", "rows", "places"]);
    expect(acceptField(SERVER, "scan", SCAN, "places").tool_facts).toEqual({
      ...MARK,
      scan: { kind: "signature_rules", rows: "/matches/*", places: { offset: "/strings/*/offset" } },
    });
    expect(acceptField(SERVER, "scan", SCAN, "display_name").tool_facts).toEqual({
      ...MARK,
      scan: { display_name: "Rule scanner" },
    });
    expect(alsoStaged(SERVER, "scan", SCAN, "places")).toEqual(["kind", "rows"]);
    expect(alsoStaged(SERVER, "scan", SCAN, "display_name")).toEqual([]);
  });

  it("stages a kind only when the kind is accepted", () => {
    expect(acceptField(SERVER, "scan", SCAN, "kind").tool_facts).toEqual({
      ...MARK,
      scan: { kind: "signature_rules" },
    });
  });

  it("never overwrites a required field the operator wrote", () => {
    const server = { ...SERVER, tool_facts: { scan: { kind: "mine", rows: "/hits/*" } } };
    expect(acceptField(server, "scan", SCAN, "places").tool_facts!.scan).toEqual({
      kind: "mine",
      rows: "/hits/*",
      places: { offset: "/strings/*/offset" },
    });
    expect(alsoStaged(server, "scan", SCAN, "places")).toEqual([]);
  });

  it("replaces the field accepted itself", () => {
    const server = { ...SERVER, tool_facts: { scan: { kind: "mine", rows: "/hits/*" } } };
    const staged = acceptField(server, "scan", SCAN, "rows").tool_facts!.scan as { rows: string };
    expect(staged.rows).toBe("/matches/*");
  });

  it("stages a whole tool as proposed, and nothing for a tool proposed nothing", () => {
    const server = { ...SERVER, tool_facts: { other: { kind: "strings" } } };
    const staged = acceptTool(server, "scan", SCAN);
    expect(staged.tool_facts).toEqual({ ...MARK, other: { kind: "strings" }, scan: SCAN.facts });
    expect(isAccepted({ ...server, ...staged }, "scan", "places", SCAN)).toBe(true);
    expect(isAccepted(server, "scan", "places", SCAN)).toBe(false);
    expect(acceptTool(server, "lister", LISTER).tool_facts!.lister).toEqual(LISTER.facts);
    expect(acceptTool(server, "empty", { facts: {}, fields: {} })).toEqual({});
  });

  it("adds a server's error patterns and prefixes beside its own, once", () => {
    const pattern = { match: "cannot open .+", tools: ["scan"] };
    const server = { ...SERVER, error_patterns: [pattern], auto_name_prefixes: ["proc_"] };
    expect(
      acceptServerField(server, "error_patterns", {
        value: [pattern, { match: "no program" }],
        evidence: [],
        confidence: "medium",
      }),
    ).toEqual({ error_patterns: [pattern, { match: "no program" }] });
    expect(
      acceptServerField(server, "auto_name_prefixes", { value: ["proc_", "blk_"], evidence: [], confidence: "low" }),
    ).toEqual({ auto_name_prefixes: ["proc_", "blk_"] });
    expect(acceptServerField(server, "other", { value: 1, evidence: [], confidence: "low" })).toEqual({});
  });
});

describe("accepting on a server that ships declarations", () => {
  const FIELDS = (served as unknown as SettingsSchema).tool_declaration_fields as ToolDeclarationFields;
  /* What the server ships for `scan`, and its declaration as served (a full dump). */
  const SHIPPED = {
    scan: { ...FIELDS.kind_free, ...FIELDS.kind_dependent, kind: "strings", rows: "/m/*", display_name: "Scan" },
  };
  const DECLARED = { shipped: SHIPPED, fields: FIELDS };
  const UNCLASSIFIED: ToolProposal = {
    facts: { kind: "unclassified", display_name: "P" },
    fields: {
      kind: { value: "unclassified", evidence: ["description"], confidence: "low" },
      display_name: { value: "P", evidence: ["title"], confidence: "high" },
    },
  };
  const removed = { ...SERVER, tool_facts: { ...MARK, scan: null } } as McpServerEntry;
  const inForce = (entry: Partial<McpServerEntry>) =>
    mergeToolFacts(SHIPPED, entry.tool_facts).scan as Record<string, unknown>;
  const set = (facts: Record<string, unknown>) =>
    Object.fromEntries(
      Object.entries(facts).filter(([name, value]) => {
        const fallback = name === "kind" ? "" : { ...FIELDS.kind_free, ...FIELDS.kind_dependent }[name];
        return JSON.stringify(value) !== JSON.stringify(fallback);
      }),
    );
  const saves = (entry: Partial<McpServerEntry>) =>
    readToolFacts(JSON.stringify(mergeToolFacts(SHIPPED, entry.tool_facts)), "s", FIELDS).error;

  it("stages exactly the proposal for a shipped tool the operator removed, never the old declaration", () => {
    const staged = acceptTool(removed, "scan", UNCLASSIFIED, DECLARED);
    expect(set(inForce(staged))).toEqual({ kind: "unclassified", display_name: "P" });
    expect(staged.tool_facts).toEqual({ ...MARK, scan: { kind: "unclassified", rows: "", display_name: "P" } });
    expect(saves(staged)).toBeNull();
    expect(isAccepted({ ...removed, ...staged }, "scan", "kind", UNCLASSIFIED, DECLARED)).toBe(true);
  });

  it("stages one accepted field of a removed shipped tool with nothing of the old declaration", () => {
    const staged = acceptField(removed, "scan", UNCLASSIFIED, "kind", DECLARED);
    expect(set(inForce(staged))).toEqual({ kind: "unclassified" });
    // The no-kind word alone declares nothing, and is refused as the API refuses it,
    // rather than saved beside a shipped rows path the operator never typed.
    expect(saves(staged)).not.toBeNull();
    // A second field accepted after it keeps the first, and saves.
    const next = acceptField({ ...removed, ...staged }, "scan", UNCLASSIFIED, "display_name", DECLARED);
    expect(set(inForce(next))).toEqual({ kind: "unclassified", display_name: "P" });
    expect(saves(next)).toBeNull();
    expect(isAccepted(removed, "scan", "kind", UNCLASSIFIED, DECLARED)).toBe(false);
  });

  it("reads a partly changed shipped tool as it is in force", () => {
    const changed = { ...SERVER, tool_facts: { ...MARK, scan: { display_name: "Mine" } } } as McpServerEntry;
    // rows is set in force (shipped), so accepting places keeps it.
    expect(alsoStaged(changed, "scan", SCAN, "places", DECLARED)).toEqual([]);
    const staged = acceptField(changed, "scan", SCAN, "places", DECLARED);
    expect(staged.tool_facts).toEqual({
      ...MARK,
      scan: { display_name: "Mine", places: { offset: "/strings/*/offset" } },
    });
    expect(isAccepted(changed, "scan", "rows", SCAN, DECLARED)).toBe(false);
  });

  it("adds a required field the declaration in force holds only at its default", () => {
    const own = { ...SERVER, tool_facts: { ...MARK, mine: { kind: "signature_rules", rows: "" } } } as McpServerEntry;
    expect(alsoStaged(own, "mine", SCAN, "places", DECLARED)).toEqual(["rows"]);
    expect((acceptField(own, "mine", SCAN, "places", DECLARED).tool_facts!.mine as { rows: string }).rows).toBe(
      "/matches/*",
    );
  });
});

describe("DeclarationProposals", () => {
  it("shows the server's text as text, never as markup", () => {
    const hostile = '<img src=x onerror="alert(1)">{{attached:x}}';
    const proposals = readProposals(
      result({
        v: 1,
        tools: {
          [hostile]: {
            facts: { display_name: hostile },
            fields: { display_name: { value: hostile, evidence: [hostile], confidence: "high" } },
            notes: [hostile],
          },
        },
        server: {},
        probed: { [hostile]: hostile },
        failed: { [`${hostile}2`]: hostile },
      }),
    )!;
    const html = render(proposals);
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
  });

  it("draws an accept per field and per tool, the fields a field brings, and nothing when empty", () => {
    const proposals = readProposals(result({ v: 1, tools: { scan: SCAN }, server: {} }))!;
    const html = render(proposals);
    expect(html).toContain('aria-label="accept every field of scan"');
    for (const field of Object.keys(SCAN.fields)) expect(html).toContain(`aria-label="accept ${field}"`);
    expect(html).toContain("also stages kind, rows");
    expect(render(readProposals(result({ v: 1, tools: {}, server: {} }))!)).toBe("");
  });

  it("lists a tool proposed nothing on one line, with no accept", () => {
    const proposals = readProposals(
      result({ v: 1, tools: { quiet_one: { facts: {}, fields: {} }, quiet_two: { facts: {}, fields: {} } }, server: {} }),
    )!;
    const html = render(proposals);
    expect(html).toContain("Nothing proposed for: <span");
    expect(html).toContain("quiet_one, quiet_two");
    expect(html).not.toContain("accept every field");
  });

  it("starts closed past a handful of proposing tools", () => {
    const many = Object.fromEntries(Array.from({ length: 6 }, (_, i) => [`t${i}`, LISTER]));
    expect(render(readProposals(result({ v: 1, tools: many, server: {} }))!)).not.toContain(" open=");
    expect(render(readProposals(result({ v: 1, tools: { t: LISTER }, server: {} }))!)).toContain(" open=");
  });

  it("lists every planned call before any is made, and calls only on a confirm", () => {
    const planned = [
      { tool: "lookup", arguments: { hash: "e3" }, remote: true, credential: true, withheld: [] },
      {
        tool: "lister",
        arguments: { path: "/nonexistent-maljan-probe/x" },
        remote: false,
        credential: false,
        withheld: ["auth token", "environment HIDDEN"],
      },
      { tool: "open_one", arguments: {}, remote: false, credential: false, withheld: [] },
    ];
    const proposals = readProposals(result({ v: 1, tools: { lister: LISTER }, server: {}, planned }))!;
    const confirmed: string[][] = [];
    const html = render(proposals, { onConfirmCalls: (tools: string[]) => confirmed.push(tools) });
    expect(html).toContain('data-planned-call="lookup"');
    expect(html).toContain("may reach its own service");
    expect(html).toContain("with this server&#x27;s credential");
    expect(html).toContain("withheld: auth token, environment HIDDEN");
    expect(html).toContain("nothing withheld");
    expect(html).toContain("exactly as it is configured");
    expect(html).toContain("Call these 3 tools once each");
    // Rendering calls nothing.
    expect(confirmed).toEqual([]);
    // No confirm control without a handler, and none once the calls were made.
    expect(render(proposals)).not.toContain("Call these");
    const made = readProposals(
      result({ v: 1, tools: { lister: LISTER }, server: {}, planned, probed: { lister: "called" } }),
    )!;
    expect(render(made, { onConfirmCalls: () => {} })).not.toContain("Call these");
  });

  it("says only the accepted tools are stored, with no warning of a frozen declaration", () => {
    const proposals = readProposals(result({ v: 1, tools: { t: LISTER }, server: {} }))!;
    const html = render(proposals);
    expect(html).toContain("Only the tools you");
    expect(html).toContain("keeps following what the server ships");
    expect(html).not.toContain("stores them whole");
  });
});
