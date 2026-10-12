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
  showJson,
  splitWords,
} from "../declarationFields";

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
    expect(readToolFacts("").value).toEqual({});
    const ok = readToolFacts('{"scan": {"kind": "rule_match", "rows": "/hits/*"}}');
    expect(ok.value).toEqual({ scan: { kind: "rule_match", rows: "/hits/*" } });
    expect(readToolFacts("[]").error).toMatch(/keyed by tool name/);
    // A declaration may name no kind.
    expect(readToolFacts('{"scan": {}}').error).toBeNull();
    expect(readToolFacts('{"scan": {"kind": 3}}').error).toMatch(/scan: kind is a lowercase word/);
    expect(readToolFacts('{"scan": {"kind": "Rule Match"}}').error).toMatch(/scan: kind/);
  });

  it("shows nothing declared as an empty box and a value as pretty JSON", () => {
    expect(showJson(undefined)).toBe("");
    expect(showJson([])).toBe("");
    expect(showJson({})).toBe("");
    expect(showJson({ a: { kind: "strings" } })).toContain('"kind": "strings"');
  });

  it("refuses a tool name that is empty, padded or this server's renamed spelling", () => {
    expect(readToolFacts('{"": {"kind": "strings"}}').error).toMatch(/own name/);
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
