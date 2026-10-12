import { describe, expect, it } from "vitest";
import {
  readEnvNames,
  readErrorPatterns,
  readMount,
  readPrefixes,
  readReferenceUrls,
  readRoles,
  readToolFacts,
  readWorkDir,
  readsNoKind,
  showJson,
  splitWords,
} from "../declarationFields";
import served from "@/test-fixtures/settings-schema.json";
import shared from "@/test-fixtures/tool-declaration-cases.json";
import type { SettingsSchema, ToolDeclarationFields } from "@/types/settings";

/* The split the API serves with the settings schema, as the box reads it. */
const FIELDS = (served as unknown as SettingsSchema).tool_declaration_fields as ToolDeclarationFields;
const read = (text: string, serverKey = "") => readToolFacts(text, serverKey, FIELDS);

describe("the server editor's declaration readers", () => {
  it("reads roles as lowercase words, comma- or line-separated, any word accepted", () => {
    expect(readRoles("reputation, my_own_role\nsandbox,")).toEqual({
      value: ["reputation", "my_own_role", "sandbox"],
      error: null,
    });
    expect(readRoles("Reputation").error).toMatch(/not a role word: Reputation/);
    expect(readRoles("").value).toEqual([]);
  });

  it("reads environment names one per line and names a bad one", () => {
    expect(readEnvNames("MY_DIR\nOTHER").value).toEqual(["MY_DIR", "OTHER"]);
    expect(readEnvNames("NOT-A-NAME").error).toMatch(/NOT-A-NAME/);
  });

  it("reads a mount as an absolute path or nothing", () => {
    expect(readMount(" /data/in ").value).toBe("/data/in");
    expect(readMount("").value).toBe("");
    expect(readMount("data/in").error).toMatch(/absolute path/);
  });

  it("reads error patterns as a list of objects with a match", () => {
    expect(readErrorPatterns("").value).toEqual([]);
    const ok = readErrorPatterns('[{"match": "No file .*", "code": "tool_failed"}]');
    expect(ok.value).toEqual([{ match: "No file .*", code: "tool_failed" }]);
    expect(readErrorPatterns("[{").error).toMatch(/not valid JSON/);
    expect(readErrorPatterns('{"match": "x"}').error).toMatch(/expected a list/);
    expect(readErrorPatterns('[{"code": "tool_failed"}]').error).toMatch(/pattern 1 needs a match/);
    expect(readErrorPatterns('[{"match": "x", "code": "Bad Code"}]').error).toMatch(/lowercase word/);
  });

  it("reads tool declarations as an object of tools each with a kind word", () => {
    expect(read("").value).toEqual({});
    const ok = read('{"scan": {"kind": "rule_match", "rows": "/hits/*"}}');
    expect(ok.value).toEqual({ scan: { kind: "rule_match", rows: "/hits/*" } });
    expect(read("[]").error).toMatch(/keyed by tool name/);
    // An empty declaration, a misspelt key and a kind-dependent field with
    // no kind are refused, as the API refuses them.
    expect(read('{"scan": {}}').error).toMatch(/scan: name its kind/);
    expect(read('{"scan": {"knd": "decompile"}}').error).toMatch(/scan: unknown field knd/);
    expect(read('{"scan": {"rows": "/m/*", "places": {"offset": "/o"}}}').error).toMatch(
      /scan: (rows, places|places, rows) are read only through a kind/
    );
    // A declaration of no kind states only kind-free fields.
    expect(read('{"scan": {"display_name": "Scanner"}}').error).toBeNull();
    expect(read('{"scan": {"kind": 3}}').error).toMatch(/scan: kind is a lowercase word/);
    expect(read('{"scan": {"kind": "Rule Match"}}').error).toMatch(/scan: kind/);
  });

  it("reads the no-kind word as the API does: an ordinary kind beside a kind-dependent field", () => {
    // A dev-era server declaration stays editable, and another tool can be added beside it.
    const devEra = read('{"t": {"kind": "unclassified", "rows": "/m/*"}, "u": {"kind": "strings"}}');
    expect(devEra.error).toBeNull();
    expect(devEra.value?.t).toEqual({ kind: "unclassified", rows: "/m/*" });
    // Alone, or with only defaults, it still names no kind and declares nothing.
    expect(read('{"t": {"kind": "unclassified"}}').error).toMatch(/t: name its kind/);
    expect(read('{"t": {"kind": "unclassified", "rows": ""}}').error).toMatch(/t: name its kind/);
    expect(read('{"t": {"kind": "unclassified", "display_name": "X"}}').error).toBeNull();
  });

  it("counts a field as set only when it differs from its default, as the API counts it", () => {
    // An accepted kindless proposal, stored as the full declaration with every default.
    const stored = shared.cases.find((c) => c.name.startsWith("an accepted kindless proposal"));
    expect(stored).toBeDefined();
    const box = JSON.stringify({ proposed: stored?.declaration, other: { kind: "strings" } });
    expect(read(box).error).toBeNull();
    expect(read('{"t": {"display_name": "X", "rows": ""}}').error).toBeNull();
  });

  it("without the served split, checks the shape and leaves the field rules to the API", () => {
    expect(readToolFacts('{"t": {"kind": "unclassified", "rows": "/m/*"}}').error).toBeNull();
    expect(readToolFacts('{"t": {"kind": "Rule Match"}}').error).toMatch(/t: kind/);
    expect(readToolFacts("[]").error).toMatch(/keyed by tool name/);
  });

  it.each(shared.cases.map((c) => [c.name, c] as const))(
    "reads the shared case %s exactly as the API does",
    (_name, c) => {
      const facts = c.declaration as Record<string, unknown>;
      expect(read(JSON.stringify({ t: facts })).error === null).toBe(c.accepted);
      expect(readsNoKind(facts, FIELDS)).toBe(c.reads_no_kind);
    }
  );

  it("shows nothing declared as an empty box and a value as pretty JSON", () => {
    expect(showJson(undefined)).toBe("");
    expect(showJson([])).toBe("");
    expect(showJson({})).toBe("");
    expect(showJson({ a: { kind: "strings" } })).toContain('"kind": "strings"');
  });

  it("refuses a tool name that is empty, padded or this server's renamed spelling", () => {
    expect(read('{"": {"kind": "strings"}}').error).toMatch(/own name/);
    expect(readToolFacts('{" x": {"kind": "strings"}}').error).toMatch(/own name/);
    expect(readToolFacts('{"mine__capa": {"kind": "strings"}}', "mine").error).toMatch(
      /renamed tool/
    );
  });

  it("accepts a tool whose own name holds a double underscore", () => {
    const read = readToolFacts('{"get__thing": {"kind": "strings"}}', "mine");
    expect(read.value).toEqual({ get__thing: { kind: "strings" } });
    expect(readToolFacts('{"other__x": {"kind": "strings"}}', "mine").error).toBeNull();
  });

  it("reads a work directory as one name", () => {
    expect(readWorkDir("r2-work").value).toBe("r2-work");
    expect(readWorkDir("a/b").error).toMatch(/one directory name/);
    expect(readWorkDir("..").error).toMatch(/one directory name/);
  });

  it("reads auto-name prefixes ending in _ or .", () => {
    expect(readPrefixes("FUN_, fcn.").value).toEqual(["FUN_", "fcn."]);
    expect(readPrefixes("FUN").error).toMatch(/not a prefix: FUN/);
  });

  it("reads reference URL templates naming a hash", () => {
    const url = "https://example.org/sample/{sha256}";
    expect(readReferenceUrls(url).value).toEqual([url]);
    expect(readReferenceUrls("http://example.org/{sha256}").error).toMatch(/https/);
    expect(readReferenceUrls("https://example.org/").error).toMatch(/sha256/);
  });

  it("splits words without keeping empty entries", () => {
    expect(splitWords(" a ,\n\n b ")).toEqual(["a", "b"]);
  });
});
