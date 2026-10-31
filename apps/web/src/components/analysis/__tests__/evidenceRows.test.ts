import { describe, expect, it } from "vitest";

import type { EvidenceEntry } from "@/types/evidence";
import {
  ARGS_SUMMARY_CHARS,
  EMPTY_OPTIONS,
  EVIDENCE_PAGE_SIZE,
  NO_FILTERS,
  structuredOutput,
  MAX_PARSED_OUTPUT_CHARS,
  argsSummary,
  deepLinkView,
  emptyOutputNote,
  evidenceQuery,
  formatCallDuration,
  mergeOptions,
  outputPreview,
  pageCount,
  pageOfEntry,
  withFilter,
} from "../evidenceRows";

function entry(over: Partial<EvidenceEntry> = {}): EvidenceEntry {
  return {
    id: "1",
    entry_id: "ev_0001",
    stage: "analysis",
    agent: "static",
    server: "analysis",
    tool: "pe_info",
    ok: true,
    duration_ms: 120,
    seq: 1,
    args: null,
    output: "",
    structured: null,
    created_at: null,
    ...over,
  };
}

describe("the query one page is fetched with", () => {
  it("asks for the page and nothing else when no filter is set", () => {
    expect(evidenceQuery(NO_FILTERS, 3)).toEqual({ page: 3, pageSize: EVIDENCE_PAGE_SIZE });
  });

  it("sends each filter the operator set, and only those", () => {
    expect(evidenceQuery({ stage: "verdict", agent: "", tool: "capa" }, 1)).toEqual({
      page: 1,
      pageSize: EVIDENCE_PAGE_SIZE,
      stage: "verdict",
      tool: "capa",
    });
  });

  it("never asks for a page below the first", () => {
    expect(evidenceQuery(NO_FILTERS, 0).page).toBe(1);
  });
});

describe("paging", () => {
  it("counts the pages a total fills", () => {
    expect(pageCount(0)).toBe(1);
    expect(pageCount(50)).toBe(1);
    expect(pageCount(51)).toBe(2);
    expect(pageCount(120)).toBe(3);
  });

  it("goes back to the first page whenever a filter changes", () => {
    const next = withFilter({ stage: "", agent: "", tool: "" }, "agent", "reverser");
    expect(next.page).toBe(1);
    expect(next.filters).toEqual({ stage: "", agent: "reverser", tool: "" });
  });

  it("keeps the filters that were not touched", () => {
    const next = withFilter({ stage: "triage", agent: "", tool: "" }, "tool", "strings");
    expect(next.filters.stage).toBe("triage");
  });
});

describe("a citation deep link", () => {
  it("derives the page from the id rather than searching for it", () => {
    expect(pageOfEntry("ev_0001")).toBe(1);
    expect(pageOfEntry("ev_0050")).toBe(1);
    expect(pageOfEntry("ev_0051")).toBe(2);
    expect(pageOfEntry("ev_0140")).toBe(3);
  });

  it("refuses anything that is not one of our ids", () => {
    expect(pageOfEntry("")).toBeNull();
    expect(pageOfEntry("ev_")).toBeNull();
    expect(pageOfEntry("ev_0000")).toBeNull();
    expect(pageOfEntry("finding-3")).toBeNull();
  });

  it("clears the filters, because a filter would hide the entry it points at", () => {
    const view = deepLinkView("ev_0051");
    expect(view).toEqual({ filters: NO_FILTERS, page: 2 });
  });

  it("is nothing at all when the id does not parse", () => {
    expect(deepLinkView("nonsense")).toBeNull();
  });
});

describe("the arguments cell", () => {
  it("is empty for a call that took none", () => {
    expect(argsSummary(null)).toEqual({ text: "", truncated: false });
    expect(argsSummary({})).toEqual({ text: "", truncated: false });
  });

  it("prints a short argument object whole", () => {
    expect(argsSummary({ path: "/tmp/a" })).toEqual({
      text: '{"path":"/tmp/a"}',
      truncated: false,
    });
  });

  it("cuts a long one and says it was cut", () => {
    const summary = argsSummary({ blob: "x".repeat(400) });
    expect(summary.truncated).toBe(true);
    expect(summary.text).toHaveLength(ARGS_SUMMARY_CHARS + 1);
  });

});

describe("the output disclosure", () => {
  it("lays out an output that is a JSON object or list, and leaves text as text", () => {
    expect(structuredOutput('{"pid": 4, "rows": [{"a": 1}]}')).toEqual({ pid: 4, rows: [{ a: 1 }] });
    expect(structuredOutput("  [1, 2]\n")).toEqual([1, 2]);
    // A scalar, prose, a broken document and an empty output are text.
    for (const text of ["42", '"a"', "found 3 strings", "{not json", "", null]) {
      expect(structuredOutput(text)).toBeNull();
    }
    expect(structuredOutput(`[${"1,".repeat(300_000)}1]`)).toBeNull();
  });

  it("shows an output as its text wherever laying it out would change it", () => {
    // An integer past 2^53 would lose digits.
    expect(structuredOutput('{"handle": 18446744073709551615}')).toBeNull();
    // A key written twice would fold into one.
    expect(structuredOutput('{"a": 1, "a": 2}')).toBeNull();
    // A long digit run inside a string is a string, and changes nothing.
    expect(structuredOutput('{"sha256": "123456789012345678901234"}')).toEqual({ sha256: "123456789012345678901234" });
    // Spacing is not a change.
    expect(structuredOutput('{\n  "a" : [ 1, 2 ]\n}')).toEqual({ a: [1, 2] });
  });

  it("lays out an ordinary output however it spells its numbers and strings", () => {
    // 1.0 and 1e2 read back as the numbers they wrote.
    expect(structuredOutput('{"ratio": 1.0, "count": 1e2}')).toEqual({ ratio: 1, count: 100 });
    // An escaped é and an escaped slash are spellings, not losses.
    expect(structuredOutput('{"name": "caf\\u00e9", "path": "a\\/b"}')).toEqual({ name: "café", path: "a/b" });
    // The same key in two different objects is not a repeat.
    expect(structuredOutput('[{"a": 1}, {"a": 2}]')).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("shows as text an output whose number a JavaScript number cannot hold, or whose object repeats a key", () => {
    expect(structuredOutput('{"base": 18446744071562067968}')).toBeNull();
    expect(structuredOutput('{"tiny": 1e-400}')).toBeNull();
    expect(structuredOutput('{"huge": 1e400}')).toBeNull();
    expect(structuredOutput('{"outer": {"k": 1, "k": 1}}')).toBeNull();
    // A key repeated through an escape is still the same key.
    expect(structuredOutput('{"k": 1, "\\u006b": 2}')).toBeNull();
  });

  it("shows a document nested deeper than the layout goes as its text, without throwing", () => {
    const deep = `${"[".repeat(5_000)}1${"]".repeat(5_000)}`;
    expect(() => structuredOutput(deep)).not.toThrow();
    expect(structuredOutput(deep)).toBeNull();
    expect(structuredOutput(`${"[".repeat(10)}1${"]".repeat(10)}`)).not.toBeNull();
  });

  it("shows an output above the size it lays out as its text", () => {
    expect(structuredOutput(`{"a": "${"x".repeat(MAX_PARSED_OUTPUT_CHARS)}"}`)).toBeNull();
  });

  it("shows a short output whole and offers nothing more", () => {
    expect(outputPreview("hello", false)).toEqual({ text: "hello", hidden: 0 });
  });

  it("caps a long one and counts what it is holding back", () => {
    const preview = outputPreview("y".repeat(2_500), false);
    expect(preview.text).toHaveLength(2_000);
    expect(preview.hidden).toBe(500);
  });

  it("shows everything once the reader asks", () => {
    expect(outputPreview("y".repeat(2_500), true).hidden).toBe(0);
  });
});

describe("the filter options", () => {
  it("accumulate across the pages that have come back", () => {
    const first = mergeOptions(EMPTY_OPTIONS, [
      entry({ stage: "triage", agent: "triage", tool: "file_info" }),
    ]);
    const second = mergeOptions(first, [
      entry({ stage: "analysis", agent: "static", tool: "pe_info" }),
    ]);
    expect(second.stage).toEqual(["analysis", "triage"]);
    expect(second.agent).toEqual(["static", "triage"]);
    expect(second.tool).toEqual(["file_info", "pe_info"]);
  });

  it("keep an option that the page it came from no longer contains", () => {
    const seen = mergeOptions(EMPTY_OPTIONS, [entry({ agent: "network" })]);
    expect(mergeOptions(seen, [entry({ agent: "static" })]).agent).toEqual([
      "network",
      "static",
    ]);
  });

  it("leave out the built-in server, which has no name", () => {
    const seen = mergeOptions(EMPTY_OPTIONS, [entry({ server: null })]);
    expect(seen.tool).toEqual(["pe_info"]);
  });
});

describe("a call's duration", () => {
  it("is milliseconds under a second and seconds over one", () => {
    expect(formatCallDuration(0)).toBe("0 ms");
    expect(formatCallDuration(999)).toBe("999 ms");
    expect(formatCallDuration(1_500)).toBe("1.5 s");
  });
});

describe("what an empty output is explained by", () => {
  it("names the byte budget only for an entry that says it was trimmed", () => {
    const note = emptyOutputNote(entry({ output: "", truncated: true }));
    expect(note).toContain("byte budget");
    expect(note).toContain("its outcome stand");
  });

  it("does not explain a failed call as a trimmed one", () => {
    /* A failed call has an empty output too. Reading the emptiness as a trim
     * printed the budget sentence directly under the failure row. */
    const note = emptyOutputNote(
      entry({ output: "", ok: false, error: "the tool server did not answer" }),
    );
    expect(note).not.toContain("byte budget");
    expect(note).toBe("This call recorded no output.");
  });

  it("asserts nothing for a row recorded before the flag existed", () => {
    expect(emptyOutputNote(entry({ output: "" }))).toBe("This call recorded no output.");
  });
});
