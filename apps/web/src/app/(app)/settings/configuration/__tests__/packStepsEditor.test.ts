import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { deepEqual } from "../deepEqual";
import schema from "@/test-fixtures/settings-schema.json";
import cases from "@/test-fixtures/pack-step-placeholder-cases.json";
import layering from "@/test-fixtures/pack-step-layering-cases.json";
import writtenByHand from "@/test-fixtures/pack-steps-written-by-hand.json";
import type { CatalogEntry, McpServerEntry, PackStepVocabulary } from "@/types/settings";
import FieldRow from "../FieldRow";
import PackStepsEditor from "../PackStepsEditor";
import {
  argumentRows,
  canonicalStep,
  clearedValue,
  dropItem,
  fieldOf,
  idProblems,
  inForce,
  moveItem,
  newStepError,
  offeredTools,
  readArgumentRows,
  readNumber,
  readSteps,
  readText,
  replaceItem,
  staleListings,
  standing,
  stateKeyNote,
  toolNote,
  typeProblems,
  unknownFields,
  unknownPlaceholders,
  withField,
  type StepValue,
} from "../packSteps";
import { EMPTY_SERVER } from "../ServerMapEditor";

/** The steps' catalog entry exactly as the API serves it (the served-schema
 *  fixture, which a backend test holds to the live schema). */
function servedEntry(): CatalogEntry {
  for (const group of (schema as unknown as { groups: { entries: CatalogEntry[] }[] }).groups) {
    for (const entry of group.entries) {
      if (entry.editor === "pack_steps") return entry;
    }
  }
  throw new Error("no pack_steps entry in the served schema");
}

const entry = servedEntry();
const vocabulary = entry.pack_step_vocabulary as PackStepVocabulary;

const servers: Record<string, McpServerEntry> = {
  acmescan: { ...EMPTY_SERVER, tools: ["scan_file", "scan_memory"] },
  open: { ...EMPTY_SERVER, tools: null },
};

/** The steps of the hand-written fixture, built through the form's own edits. */
function builtThroughTheForm(order: "fields first" | "budget first"): StepValue[] {
  let steps: StepValue[] = [];
  steps = [...steps, { id: "acme_scan" }];
  const edits: [string, unknown][] = [
    ["server", "acmescan"],
    ["tool", "scan_file"],
    [
      "arguments",
      (readArgumentRows([
        { name: "path", value: "{sample_path}" },
        { name: "options", value: "--hash {sha256} --as {file_type}" },
      ]) as { value: Record<string, unknown> }).value,
    ],
    ["formats", ["pe", "elf"]],
    ["budget_seconds", (readNumber("90", vocabulary.fields.find((f) => f.name === "budget_seconds")!) as { value: unknown }).value],
  ];
  const ordered = order === "fields first" ? edits : [...edits].reverse();
  for (const [name, value] of ordered) {
    steps = replaceItem(steps, 0, withField(steps[0], name, value, vocabulary));
  }
  steps = [...steps, { id: "strings" }];
  steps = replaceItem(steps, 1, withField(steps[1], "enabled", false, vocabulary));
  return steps;
}

function render(value: unknown, extra: Partial<Parameters<typeof PackStepsEditor>[0]> = {}): string {
  return renderToStaticMarkup(
    createElement(PackStepsEditor, {
      entry,
      current: { value, is_set: null, hint: null, source: "ui", updated_at: null, updated_by: null },
      staged: undefined,
      errors: {},
      servers,
      onChange: () => undefined,
      ...extra,
    }),
  );
}

describe("the served vocabulary", () => {
  it("rides on the steps' entry, with the model's fields in its order", () => {
    expect(entry.key).toBe("core.triage.steps");
    expect(vocabulary.fields[0]).toMatchObject({ name: "id", required: true });
    expect(vocabulary.fields.map((f) => f.name)).toContain("budget_seconds");
    expect(vocabulary.formats).toContain("pe");
    expect(vocabulary.shipped.map((s) => s.id)).toContain("strings");
  });
});

describe("a step saved through the form", () => {
  it("is byte-identical to the same steps written by hand, whatever order the edits came in", () => {
    const written = JSON.stringify(writtenByHand);
    expect(JSON.stringify(builtThroughTheForm("fields first"))).toBe(written);
    expect(JSON.stringify(builtThroughTheForm("budget first"))).toBe(written);
  });

  it("writes only the fields set: unsetting one takes its key away", () => {
    const step = withField({ id: "x", server: "acmescan" }, "tool", "scan_file", vocabulary);
    expect(JSON.stringify(step)).toBe('{"id":"x","tool":"scan_file","server":"acmescan"}');
    expect(withField(step, "tool", undefined, vocabulary)).toEqual({ id: "x", server: "acmescan" });
  });
});

describe("the round trip of add, edit, reorder and drop", () => {
  const stored: StepValue[] = [
    { id: "pe_info", enabled: false },
    { server: "acmescan", id: "acme_scan", tool: "scan_file" },
  ];

  it("adds, edits, moves and drops steps, leaving every untouched step the object it was", () => {
    let steps = [...stored, { id: "mine" }];
    expect(newStepError("mine", stored, vocabulary)).toBeNull();
    expect(newStepError("acme_scan", stored, vocabulary)).toMatch(/already declared/);
    expect(newStepError("Bad-Id", stored, vocabulary)).toMatch(/matches/);

    steps = replaceItem(steps, 2, withField(steps[2], "server", "open", vocabulary));
    steps = replaceItem(steps, 2, withField(steps[2], "tool", "count", vocabulary));
    expect(steps[0]).toBe(stored[0]);
    expect(steps[1]).toBe(stored[1]);
    expect(steps[2]).toEqual({ id: "mine", tool: "count", server: "open" });

    steps = moveItem(steps, 2, 0);
    expect(steps.map((s) => s.id)).toEqual(["mine", "pe_info", "acme_scan"]);
    steps = moveItem(steps, 0, -1);
    expect(steps.map((s) => s.id)).toEqual(["mine", "pe_info", "acme_scan"]);

    steps = dropItem(steps, 1);
    expect(steps.map((s) => s.id)).toEqual(["mine", "acme_scan"]);
    expect(steps[1]).toBe(stored[1]);
    expect(JSON.stringify(steps)).toBe(
      '[{"id":"mine","tool":"count","server":"open"},{"server":"acmescan","id":"acme_scan","tool":"scan_file"}]',
    );
  });

  it("flags a step with no id, an id that does not read and an id declared twice", () => {
    const problems = idProblems([{ id: "a" }, { id: "" }, { id: "A b" }, { id: "a" }], vocabulary);
    expect([...problems.keys()]).toEqual([1, 2, 3]);
    expect(problems.get(3)).toMatch(/declared twice/);
  });

  it("reads the whole id, so one ending in a newline is flagged as the save refuses it", () => {
    expect(newStepError("acme\n", [], vocabulary)).toMatch(/matches/);
    expect(idProblems([{ id: "acme\n" }, { id: "acme" }], vocabulary).get(0)).toMatch(/matches/);
    expect(newStepError("acme", [], vocabulary)).toBeNull();
  });

  it("takes an id the pack's own state holds as any other, and notes it only where it starts beside the pack", () => {
    expect(vocabulary.state_keys).toContain("entries");
    for (const name of vocabulary.state_keys) {
      expect(newStepError(name, [], vocabulary), name).toBeNull();
    }
    expect(idProblems([{ id: "entries", server: "acmescan", tool: "scan_file" }], vocabulary).size).toBe(0);
    const beside = { id: "entries", server: "acmescan", tool: "scan_file", starts_after: "signing_info" };
    expect(stateKeyNote(beside, vocabulary)).toMatch(/recorded apart from that key/);
    expect(stateKeyNote({ ...beside, starts_after: "" }, vocabulary)).toBe("");
    expect(stateKeyNote({ ...beside, id: "acme_scan" }, vocabulary)).toBe("");
    const html = render([beside]);
    expect(html).toContain("data-pack-step-state-key-note");
    expect(html).not.toContain('role="alert">&#x27;entries&#x27;');
  });
});

describe("a step's standing and its values in force", () => {
  type Case = { declared: StepValue; standing: string; in_force: Record<string, unknown> };

  it("are read by the save's layering, case for case", () => {
    for (const { declared, standing: expected, in_force } of layering as Case[]) {
      const said = JSON.stringify(declared);
      expect(standing(declared, vocabulary), said).toBe(expected);
      for (const [name, value] of Object.entries(in_force)) {
        const field = fieldOf(vocabulary, name);
        expect(field, name).toBeDefined();
        expect(deepEqual(inForce(declared, field!, vocabulary), value), `${said} ${name}`).toBe(true);
      }
    }
  });

  it("never draws a swapped step's shipped values as in force", () => {
    const html = render([{ id: "pe_info", server: "acmescan", tool: "scan_file" }]);
    expect(html).toContain('data-pack-step-standing="replaces"');
    expect(html).toContain("replaces the shipped step pe_info");
    expect(html).not.toContain("shipped pe");
    expect(html).not.toContain("shipped: pe_header");
    expect(html).toContain(">every format<");
  });

  it("draws a step that changes its shipped step with the shipped values it keeps", () => {
    const html = render([{ id: "pe_info", enabled: false }]);
    expect(html).toContain('data-pack-step-standing="over"');
    expect(html).toContain("changes the shipped step pe_info (pe) in its place");
    expect(html).toContain("unset: shipped pe");
    expect(html).toContain("unset: shipped pe_header");
  });
});

describe("an explicit empty value over a shipped one", () => {
  const display = fieldOf(vocabulary, "display_name")!;

  it("is what emptying a box writes over a shipped value, and nothing where empty is what it holds", () => {
    expect(clearedValue({ id: "hashes" }, display, vocabulary)).toBe("");
    expect(clearedValue({ id: "acme_scan", server: "acmescan", tool: "t" }, display, vocabulary)).toBeUndefined();
    expect(clearedValue({ id: "pe_info", server: "acmescan", tool: "t" }, display, vocabulary)).toBeUndefined();
    expect(readText("", clearedValue({ id: "hashes" }, display, vocabulary))).toEqual({ value: "" });
    const beside = fieldOf(vocabulary, "beside")!;
    expect(clearedValue({ id: "floss" }, beside, vocabulary)).toEqual([]);
    const peak = fieldOf(vocabulary, "peak_mb")!;
    expect(clearedValue({ id: "floss" }, peak, vocabulary)).toBeNull();
  });

  it("is drawn as set, in place of the shipped value, with a way to unset it", () => {
    const html = render([
      { id: "hashes", display_name: "" },
      { id: "identify_file", renderer: "" },
      { id: "floss", beside: [] },
    ]);
    expect(html).toContain("set to empty, in place of the shipped hashes");
    expect(html).toContain("set to empty, in place of the shipped capa");
    expect(html).toContain('aria-label="Unset display_name of step 1"');
    expect(html).toContain('<option value="(empty)" selected="">empty: the generic line, in place of the shipped identity</option>');
  });

  it("can be written where a shipped value stands, and is not offered where it would mean nothing", () => {
    const html = render([
      { id: "hashes" },
      { id: "acme_scan", server: "acmescan", tool: "scan_file" },
      { id: "pe_info" },
    ]);
    expect(html).toContain('aria-label="Set display_name of step 1 to empty"');
    expect(html).not.toContain('aria-label="Set display_name of step 2 to empty"');
    expect(html).not.toContain('aria-label="Set formats of step 1 to every format"');
    expect(html).toContain('aria-label="Set formats of step 3 to every format"');
  });

  it("is drawn for formats as every format, in place of the shipped ones", () => {
    const html = render([{ id: "pe_info", formats: [] }]);
    expect(html).toContain("set to none: every format, in place of the shipped pe");
    expect(html).toContain('aria-label="Unset formats of step 1"');
  });
});

describe("a field the API does not know", () => {
  const stored: StepValue = { id: "acme_scan", colour: "blue", server: "acmescan", tool: "scan_file" };

  it("is kept through an edit of another field, after the known ones", () => {
    const edited = withField(stored, "tool", "scan_memory", vocabulary);
    expect(unknownFields(edited, vocabulary)).toEqual(["colour"]);
    expect(Object.keys(edited)).toEqual(["id", "tool", "server", "colour"]);
    expect(edited.colour).toBe("blue");
  });

  it("is kept under any name, the object's own prototype name included", () => {
    const odd = JSON.parse('{"id":"x","__proto__":{"y":1}}') as StepValue;
    const kept = canonicalStep(withField(odd, "tool", "t", vocabulary), vocabulary);
    expect(JSON.stringify(kept)).toBe('{"id":"x","tool":"t","__proto__":{"y":1}}');
  });

  it("is drawn on its card with a way to remove it", () => {
    const html = render([stored]);
    expect(html).toContain('data-pack-step-unknown-field="colour"');
    expect(html).toContain('aria-label="Remove field colour of step 1"');
  });
});

describe("a known field holding a value of another type", () => {
  const stored: StepValue = { id: "odd", server: 3, formats: "pe", enabled: "yes", arguments: "x" };

  it("is named by the type the API serves for it", () => {
    expect(typeProblems(stored, vocabulary)).toEqual([
      "server holds 3, not text; edit it as JSON",
      "arguments holds \"x\", not an object; edit it as JSON",
      "formats holds \"pe\", not a list of text; edit it as JSON",
      "enabled holds \"yes\", not true or false; edit it as JSON",
    ]);
    expect(typeProblems({ id: "fine", budget_seconds: null, formats: ["pe"] }, vocabulary)).toEqual([]);
  });

  it("is shown as it is, never drawn into a control that would replace it", () => {
    const html = render([stored]);
    expect(html).toContain("server holds 3, not text");
    for (const label of ["step 1 server", "step 1 format pe", "step 1 enabled", "step 1 argument 1 name"]) {
      expect(html, label).not.toContain(`aria-label="${label}"`);
    }
    expect(html).toContain('aria-label="step 1 tool"');
  });
});

describe("the placeholder check", () => {
  it("reads every case as the save does, by the served pattern and list", () => {
    for (const { text, unknown } of cases as { text: string; unknown: string[] }[]) {
      const found = unknownPlaceholders({ a: text }, vocabulary).map((f) => f.placeholder);
      expect(found, text).toEqual(unknown);
    }
  });

  it("passes every placeholder the API serves, and only those", () => {
    for (const term of vocabulary.placeholders) {
      expect(unknownPlaceholders({ a: `{${term.name}}` }, vocabulary)).toEqual([]);
    }
    const narrowed = { ...vocabulary, placeholders: vocabulary.placeholders.slice(1) };
    const first = vocabulary.placeholders[0].name;
    expect(unknownPlaceholders({ a: `{${first}}` }, narrowed)).toEqual([
      { argument: "a", placeholder: first },
    ]);
  });

  it("reads a string at any depth and names the argument holding it", () => {
    const template = { path: "{sample_path}", nested: [{ deep: ["{nope}", { deeper: "{also}" }] }] };
    expect(unknownPlaceholders(template, vocabulary)).toEqual([
      { argument: "nested", placeholder: "nope" },
      { argument: "nested", placeholder: "also" },
    ]);
  });

  it("is flagged on the argument's row before Apply", () => {
    const html = render([{ id: "x", server: "acmescan", tool: "scan_file", arguments: { p: "{nope}" } }]);
    expect(html).toContain("names {nope}, which a template cannot name");
  });

  it("stays linear in the template's size, deep or wide", () => {
    const deep = (n: number) => {
      let held: unknown = "{sample_path}{bad}";
      for (let i = 0; i < n; i += 1) held = [{ inner: held }];
      return { a: held };
    };
    const wide = (n: number) => ({ a: Array.from({ length: n }, () => "{sha256} {bad} ".repeat(4)) });
    const took = (template: unknown, expected: number) => {
      const started = performance.now();
      expect(unknownPlaceholders(template, vocabulary)).toHaveLength(expected);
      return performance.now() - started;
    };
    took(deep(500), 1);
    const deepSmall = took(deep(2_000), 1);
    const deepLarge = took(deep(20_000), 1);
    expect(deepLarge).toBeLessThan(Math.max(deepSmall * 40, 50));
    const wideSmall = took(wide(2_000), 8_000);
    const wideLarge = took(wide(20_000), 80_000);
    expect(wideLarge).toBeLessThan(Math.max(wideSmall * 40, 50));
  });
});

describe("the argument rows", () => {
  it("read back into the template in their order, a value that is not text kept", () => {
    const rows = argumentRows({ path: "{sample_path}", depth: 3 });
    expect(rows).toEqual([
      { name: "path", value: "{sample_path}" },
      { name: "depth", value: 3 },
    ]);
    expect(readArgumentRows(rows)).toEqual({ value: { path: "{sample_path}", depth: 3 } });
  });

  it("cannot be written with a row that has no name or a name given twice", () => {
    expect(readArgumentRows([{ name: "", value: "x" }])).toEqual({ error: "argument 1 has no name" });
    expect(readArgumentRows([{ name: "a", value: "1" }, { name: "a", value: "2" }])).toEqual({
      error: "argument 'a' is named twice",
    });
  });
});

describe("the tool picker", () => {
  const declared = {
    ...EMPTY_SERVER,
    tools: null,
    tool_facts: { "": "changes", own: { kind: "file_iocs" }, gone: null },
  } as McpServerEntry;
  const on = (server: string, tool?: string): StepValue => ({
    id: "acme_scan",
    server,
    ...(tool === undefined ? {} : { tool }),
  });

  it("offers a server's tool list, its declared tools and what a listing reported", () => {
    expect(offeredTools({ step: on("acmescan"), servers, listed: null, vocabulary })).toEqual({
      offered: ["scan_file", "scan_memory"],
      refused: [],
    });
    expect(
      offeredTools({ step: on("d"), servers: { d: declared }, listed: ["listed"], vocabulary }),
    ).toEqual({ offered: ["own", "listed"], refused: [] });
  });

  it("never offers a listed tool outside the server's tools list, and says why with the save's words", () => {
    const offer = offeredTools({
      step: on("acmescan"),
      servers,
      listed: ["scan_file", "scan_url"],
      vocabulary,
    });
    expect(offer.offered).toEqual(["scan_file", "scan_memory"]);
    expect(offer.refused).toEqual([
      { name: "scan_url", reason: "'scan_url' is not allowed on server 'acmescan'" },
    ]);
    expect(toolNote({ step: on("acmescan", "scan_url"), servers, listed: null, vocabulary })).toEqual({
      level: "error",
      text: "'scan_url' is not allowed on server 'acmescan'",
    });
    const html = render([on("acmescan", "scan_file")]);
    expect(html).not.toContain('<option value="scan_url">');
  });

  it("names no refusal on a disabled step that the save does not make", () => {
    const off = { ...on("acmescan", "scan_url"), enabled: false };
    expect(toolNote({ step: off, servers, listed: null, vocabulary })).toEqual({
      level: "note",
      text: "'scan_url' is not allowed on server 'acmescan': the save refuses it once the step is enabled",
    });
    const html = render([off]);
    expect(html).not.toContain('data-pack-step-tool-note="error"');
    expect(html).toContain('data-pack-step-tool-note="note"');
    const listed = render([{ ...on("acmescan", "scan_file"), enabled: false }], {
      servers: {
        acmescan: { ...servers.acmescan, tool_facts: { scan_url: { kind: "file_iocs" } } } as McpServerEntry,
      },
    });
    expect(listed).toContain("Not offered, as the save refuses them once the step is enabled");
  });

  it("offers a step with no server only the tool its own shipped step calls", () => {
    expect(offeredTools({ step: { id: "strings" }, servers, listed: null, vocabulary })).toEqual({
      offered: ["strings"],
      refused: [],
    });
    expect(
      offeredTools({ step: { id: "resolved_api_capability" }, servers, listed: null, vocabulary }),
    ).toEqual({ offered: ["api_capability"], refused: [] });
    expect(toolNote({ step: { id: "strings" }, servers, listed: null, vocabulary })).toBeNull();
    expect(toolNote({ step: { id: "strings", tool: "pe_info" }, servers, listed: null, vocabulary })).toEqual({
      level: "error",
      text: "step 'strings' names no server, and is not one of the platform's own steps: name the server whose tool it is",
    });
    expect(offeredTools({ step: { id: "mine" }, servers, listed: null, vocabulary }).offered).toEqual([]);
    expect(toolNote({ step: { id: "mine" }, servers, listed: null, vocabulary })?.level).toBe("error");
  });

  it("notes a typed tool no source names, and says where it looked", () => {
    expect(toolNote({ step: on("acmescan", "scan_file"), servers, listed: null, vocabulary })).toBeNull();
    expect(toolNote({ step: on("open", "other"), servers, listed: null, vocabulary })).toEqual({
      level: "note",
      text: "'other' was not seen among open's declared tools; List tools asks the server for its manifest",
    });
    expect(toolNote({ step: on("open", "other"), servers, listed: ["x"], vocabulary })).toEqual({
      level: "note",
      text: "'other' was not seen among open's declared tools or in its manifest",
    });
    expect(toolNote({ step: on("open"), servers, listed: null, vocabulary })).toEqual({
      level: "error",
      text: "step 'acme_scan' names a server and no tool to call on it",
    });
  });

  it("drops a listing once its server's staged settings change", () => {
    const listings = { acmescan: { config: servers.acmescan }, open: { config: servers.open } };
    expect(staleListings(listings, servers)).toEqual([]);
    const edited = { ...servers, acmescan: { ...servers.acmescan, command: "acme --v2" } };
    expect(staleListings(listings, edited)).toEqual(["acmescan"]);
    const without = Object.fromEntries(Object.entries(servers).filter(([key]) => key !== "open"));
    expect(staleListings(listings, without)).toEqual(["open"]);
  });

  it("reads a server named as an object's own machinery as not configured", () => {
    const html = render([{ id: "acme_scan", server: "constructor", tool: "t" }]);
    expect(html).toContain("constructor (not a configured server)");
  });
});

describe("the editor as drawn", () => {
  const steps = [
    {
      id: "acme_scan",
      tool: "scan_file",
      server: "acmescan",
      arguments: { path: "{sample_path}" },
      formats: ["pe", "elfish"],
      budget_seconds: 90,
    },
    { id: "strings", enabled: false },
  ];

  it("draws the steps as a form, never as JSON alone", () => {
    const html = render(steps);
    expect(html).toContain('data-pack-steps-editor="form"');
    for (const label of [
      "step 1 id",
      "step 1 server",
      "step 1 tool",
      "step 1 argument 1 name",
      "step 1 argument 1 value",
      "step 1 budget_seconds",
      "step 1 format pe",
      "step 2 enabled",
      "Move step strings up",
      "Drop step acme_scan",
      "New step id",
    ]) {
      expect(html, label).toContain(`aria-label="${label}"`);
    }
    expect(html).not.toContain("as JSON\"");
    expect(html).toContain("Edit as JSON (advanced)");
  });

  it("offers every served format, and keeps a stored one the router does not give, marked", () => {
    const html = render(steps);
    for (const format of vocabulary.formats) {
      expect(html, format).toContain(`aria-label="step 1 format ${format}"`);
    }
    expect(html).toContain('aria-label="step 1 format elfish"');
    expect(html).toContain("(not a routed format)");
  });

  it("names the server's tools for the picker and marks a configured server", () => {
    const html = render(steps);
    expect(html).toContain('<option value="scan_memory">');
    expect(html).toContain('<option value="acmescan" selected="">acmescan</option>');
  });

  it("is the editor the settings row draws for the steps' entry", () => {
    const html = renderToStaticMarkup(
      createElement(FieldRow, {
        entry,
        current: { value: steps, is_set: null, hint: null, source: "ui", updated_at: null, updated_by: null },
        staged: undefined,
        servers,
        errors: {},
        onChange: () => undefined,
        onUnstage: () => undefined,
        onReset: () => undefined,
      }),
    );
    expect(html).toContain('data-pack-steps-editor="form"');
    expect(html).toContain('aria-label="step 1 server"');
  });

  it("falls back to JSON only where the API serves no vocabulary or the value is no list", () => {
    const older = renderToStaticMarkup(
      createElement(PackStepsEditor, {
        entry: { ...entry, pack_step_vocabulary: undefined },
        current: undefined,
        staged: steps,
        errors: {},
        servers,
        onChange: () => undefined,
      }),
    );
    expect(older).toContain('data-pack-steps-editor="json"');
    expect(render({ not: "a list" })).toContain('data-pack-steps-editor="json"');
    expect(readSteps({ not: "a list" })).toBeNull();
    expect(readSteps(undefined)).toEqual([]);
  });

  it("puts the save's nested refusals beside the steps", () => {
    const html = render(steps, { errors: { "core.triage.steps.arguments": "Value error, nope" } });
    expect(html).toContain("arguments</span>: Value error, nope");
  });
});
