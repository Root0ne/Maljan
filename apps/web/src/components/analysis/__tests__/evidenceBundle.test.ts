import { describe, expect, it } from "vitest";
import {
  BUNDLE_FORMAT,
  INDEX_ANCHOR,
  NOTES_ANCHOR,
  filterIndex,
  headingKey,
  navEntries,
  notesCiting,
  readBundle,
  resolveTarget,
  subsectionAnchors,
  type EvidenceBundle,
} from "../evidenceBundle";
import { recordsForwardHref } from "../overview";

/**
 * The evidence bundle as the Evidence tab reads it: with the anchors the
 * bundle's own HTML gives every section, subsection, note and evidence id.
 */

const BODY = {
  format: BUNDLE_FORMAT,
  report: { title: "Loader analysis", sha256: "ab".repeat(32), report_id: null, generated_at: "2026-10-30T10:00:00Z" },
  notes: [
    { number: 1, anchor: "cite-1", section: "Executive summary", evidence_ids: ["ev_0001", "ev_0002"] },
    { number: 2, anchor: "cite-2", section: "Detection", evidence_ids: ["ev_0003", "ev_0099"] },
  ],
  evidence_index: [
    { id: "ev_0001", agent: "pipeline", server: "pipeline", tool: "pe_info", ok: true, duration_ms: 2, truncated: false, repeated_of: null },
    { id: "ev_0002", agent: "static", server: "analysis", tool: "strings", ok: true, duration_ms: 9, truncated: true, repeated_of: null },
    { id: "ev_0003", agent: "static", server: "reputation", tool: "file_report", ok: false, duration_ms: 40, truncated: false, repeated_of: null },
    { id: "ev_0004", agent: "static", server: "analysis", tool: "strings", ok: true, duration_ms: 0, truncated: false, repeated_of: "ev_0002" },
  ],
  sections: [
    { anchor: "title", title: "Title", markdown: "# Evidence bundle: Loader analysis" },
    {
      anchor: "sec-technical-analysis",
      title: "Technical analysis",
      markdown: "## 5. Technical analysis\n\n### 5.1 Packing · _Source per row_\n\ntext\n\n### Process tree\n",
    },
    { anchor: "sec-observed-behaviour", title: "Observed behaviour", markdown: "## 6. Observed behaviour\n\n### Process tree\n" },
    { anchor: INDEX_ANCHOR, title: "Evidence index", markdown: "## Appendix A. Evidence index\n\n| ID |\n|---|\n| ev_0001 |" },
    { anchor: NOTES_ANCHOR, title: "Notes cited by the analyst report", markdown: "## Appendix E. Notes" },
  ],
};

function bundle(): EvidenceBundle {
  const read = readBundle(JSON.stringify(BODY));
  if (!("bundle" in read)) throw new Error(read.problem);
  return read.bundle;
}

describe("reading the served bundle", () => {
  it("reads every part of the format", () => {
    const b = bundle();
    expect(b.notes.map((n) => n.anchor)).toEqual(["cite-1", "cite-2"]);
    expect(b.evidence_index).toHaveLength(4);
    expect(b.sections.map((s) => s.anchor)).toContain(INDEX_ANCHOR);
  });

  it("refuses another format by name, and a body that is not JSON", () => {
    expect(readBundle(JSON.stringify({ ...BODY, format: "something/2" }))).toEqual({
      problem: `the server sent a bundle of format "something/2", not ${BUNDLE_FORMAT}`,
    });
    expect(readBundle("<html>")).toEqual({ problem: "the server's answer is not JSON" });
  });
});

describe("anchors are the bundle HTML's anchors", () => {
  it("strips a heading's number and voice tag", () => {
    expect(headingKey("5.1 Packing, obfuscation and anti-analysis · Source per row")).toBe(
      "Packing, obfuscation and anti-analysis",
    );
    expect(headingKey("Appendix A. Evidence index · Source per subsection")).toBe("Evidence index");
  });

  it("numbers a repeated subsection title after its first use", () => {
    const anchors = subsectionAnchors(bundle().sections);
    expect(anchors.get("sec-technical-analysis")).toEqual(["sec-packing", "sec-process-tree"]);
    expect(anchors.get("sec-observed-behaviour")).toEqual(["sec-process-tree-2"]);
  });

  it("resolves an evidence id, a note, a section and a subsection", () => {
    const b = bundle();
    const entries = navEntries(b);
    const subs = subsectionAnchors(b.sections);
    expect(resolveTarget("#ev_0003", entries, subs)).toEqual({ section: INDEX_ANCHOR, focus: "ev_0003" });
    expect(resolveTarget("#cite-2", entries, subs)).toEqual({ section: NOTES_ANCHOR, focus: "cite-2" });
    expect(resolveTarget("#sec-observed-behaviour", entries, subs)).toEqual({ section: "sec-observed-behaviour", focus: null });
    expect(resolveTarget("#sec-process-tree-2", entries, subs)).toEqual({ section: "sec-observed-behaviour", focus: "sec-process-tree-2" });
    expect(resolveTarget("#nowhere", entries, subs)).toBeNull();
    expect(resolveTarget("", entries, subs)).toBeNull();
    expect(resolveTarget("#%E0%A4%A", entries, subs)).toBeNull();
  });
});

describe("a record link written before the bundle led the tab", () => {
  it("is passed on to Records with its whole query and its fragment", () => {
    expect(recordsForwardHref("j1", "evidence=ev_0003&view=full", "#out")).toBe(
      "/analysis/j1/evidence/records?evidence=ev_0003&view=full#out",
    );
    expect(recordsForwardHref("j1", "?evidence=ev_0003", "")).toBe("/analysis/j1/evidence/records?evidence=ev_0003");
  });
});

describe("the navigator", () => {
  it("lists every section with the index and notes counted", () => {
    const entries = navEntries(bundle());
    expect(entries.map((e) => e.title)).toEqual([
      "About this bundle",
      "Technical analysis",
      "Observed behaviour",
      "Evidence index",
      "Notes cited by the analyst report",
    ]);
    expect(entries.find((e) => e.anchor === INDEX_ANCHOR)?.count).toBe(4);
    expect(entries.find((e) => e.anchor === NOTES_ANCHOR)?.count).toBe(2);
  });

  it("keeps the index and the notes reachable when the sections leave them out", () => {
    const b = { ...bundle(), sections: bundle().sections.slice(0, 1) };
    expect(navEntries(b).map((e) => e.anchor)).toEqual(["title", INDEX_ANCHOR, NOTES_ANCHOR]);
  });
});

describe("the evidence index", () => {
  const rows = bundle().evidence_index;

  it("searches the id, the agent, the server and the tool", () => {
    expect(filterIndex(rows, { query: "strings", agent: "", result: "all" }).map((r) => r.id)).toEqual(["ev_0002", "ev_0004"]);
    expect(filterIndex(rows, { query: "reputation", agent: "", result: "all" }).map((r) => r.id)).toEqual(["ev_0003"]);
    expect(filterIndex(rows, { query: "EV_0001", agent: "", result: "all" }).map((r) => r.id)).toEqual(["ev_0001"]);
  });

  it("filters by agent and by result", () => {
    expect(filterIndex(rows, { query: "", agent: "pipeline", result: "all" }).map((r) => r.id)).toEqual(["ev_0001"]);
    expect(filterIndex(rows, { query: "", agent: "", result: "failed" }).map((r) => r.id)).toEqual(["ev_0003"]);
    expect(filterIndex(rows, { query: "", agent: "", result: "trimmed" }).map((r) => r.id)).toEqual(["ev_0002"]);
    expect(filterIndex(rows, { query: "", agent: "", result: "repeated" }).map((r) => r.id)).toEqual(["ev_0004"]);
  });

  it("names the notes that cite a row", () => {
    expect(notesCiting(bundle().notes, "ev_0003").map((n) => n.number)).toEqual([2]);
  });
});
