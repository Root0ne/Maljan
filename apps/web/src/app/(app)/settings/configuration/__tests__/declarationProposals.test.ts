/**
 * The declarations a probe proposes, and what accepting one stages.
 *
 * Accepting stages the field in the server's declaration, with the fields it
 * needs to validate; nothing is staged before an accept. The proposal is the
 * server's data and is shown as text.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import type { McpServerEntry, ProbeResult } from "@/types/settings";
import DeclarationProposals from "../DeclarationProposals";
import {
  acceptField,
  acceptServerField,
  acceptTool,
  isAccepted,
  readProposals,
  withRequired,
  type ToolProposal,
} from "../declarationProposals";

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
  },
};

function result(proposals: unknown): ProbeResult {
  return { ok: true, latency_ms: 1, detail: "", models: null, tools: ["scan"], details: { proposals } };
}

describe("readProposals", () => {
  it("reads a probe's proposals and leaves out a part of an odd shape", () => {
    const read = readProposals(
      result({
        v: 1,
        tools: {
          scan: SCAN,
          bad: { facts: { kind: 3 } },
          odd: "x",
          half: { facts: { kind: "unclassified" }, fields: { kind: 5, rows: { value: "/r", confidence: "sure" } } },
        },
        server: { error_patterns: { value: [{ match: "x" }], evidence: ["e"], confidence: "medium" } },
        probed: { scan: "called", other: 4 },
      }),
    );
    expect(read).not.toBeNull();
    expect(Object.keys(read!.tools)).toEqual(["scan", "half"]);
    expect(read!.tools.half.fields).toEqual({ rows: { value: "/r", evidence: [], confidence: "low" } });
    expect(read!.server.error_patterns.confidence).toBe("medium");
    expect(read!.probed).toEqual({ scan: "called" });
  });

  it("is null for a result without proposals", () => {
    expect(readProposals(null)).toBeNull();
    expect(readProposals(result(undefined))).toBeNull();
    expect(readProposals(result({ tools: [] }))).toBeNull();
  });
});

describe("accepting", () => {
  it("stages a field with the fields it needs, and nothing before", () => {
    expect(SERVER.tool_facts).toBeUndefined();
    expect(withRequired(SCAN, "places")).toEqual(["kind", "rows", "places"]);
    const staged = acceptField(SERVER, "scan", SCAN, "places");
    expect(staged.tool_facts).toEqual({
      scan: { kind: "signature_rules", rows: "/matches/*", places: { offset: "/strings/*/offset" } },
    });
  });

  it("never overwrites a required field the operator wrote", () => {
    const server = { ...SERVER, tool_facts: { scan: { kind: "mine", rows: "/hits/*" } } };
    const staged = acceptField(server, "scan", SCAN, "places");
    expect(staged.tool_facts!.scan).toEqual({
      kind: "mine",
      rows: "/hits/*",
      places: { offset: "/strings/*/offset" },
    });
  });

  it("replaces the field accepted itself", () => {
    const server = { ...SERVER, tool_facts: { scan: { kind: "mine", rows: "/hits/*" } } };
    expect(acceptField(server, "scan", SCAN, "rows").tool_facts!.scan.rows).toBe("/matches/*");
  });

  it("stages a whole tool as proposed, leaving the other tools alone", () => {
    const server = { ...SERVER, tool_facts: { other: { kind: "strings" } } };
    const staged = acceptTool(server, "scan", SCAN);
    expect(staged.tool_facts).toEqual({ other: { kind: "strings" }, scan: SCAN.facts });
    expect(isAccepted({ ...server, ...staged }, "scan", "places", SCAN)).toBe(true);
    expect(isAccepted(server, "scan", "places", SCAN)).toBe(false);
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
      acceptServerField(server, "auto_name_prefixes", {
        value: ["proc_", "blk_"],
        evidence: [],
        confidence: "low",
      }),
    ).toEqual({ auto_name_prefixes: ["proc_", "blk_"] });
    expect(acceptServerField(server, "other", { value: 1, evidence: [], confidence: "low" })).toEqual({});
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
            facts: { kind: "unclassified", display_name: hostile },
            fields: {
              display_name: { value: hostile, evidence: [hostile], confidence: "high", requires: ["kind"] },
            },
            notes: [hostile],
          },
        },
        server: {},
        probed: { [hostile]: hostile },
      }),
    )!;
    const html = renderToStaticMarkup(
      createElement(DeclarationProposals, { serverKey: "s", server: SERVER, proposals, put: () => {} }),
    );
    expect(html).not.toContain("<img");
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
  });

  it("draws an accept per field and per tool, and nothing when there is nothing to propose", () => {
    const proposals = readProposals(result({ v: 1, tools: { scan: SCAN }, server: {} }))!;
    const html = renderToStaticMarkup(
      createElement(DeclarationProposals, { serverKey: "s", server: SERVER, proposals, put: () => {} }),
    );
    expect(html).toContain('aria-label="accept every field of scan"');
    for (const field of Object.keys(SCAN.fields)) expect(html).toContain(`aria-label="accept ${field}"`);
    const empty = readProposals(result({ v: 1, tools: {}, server: {} }))!;
    expect(
      renderToStaticMarkup(
        createElement(DeclarationProposals, { serverKey: "s", server: SERVER, proposals: empty, put: () => {} }),
      ),
    ).toBe("");
  });
});
