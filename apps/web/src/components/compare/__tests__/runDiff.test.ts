import { describe, expect, it } from "vitest";
import type { JobDTO } from "@/lib/api";
import type { DiffRow, DiffSection, DiffStatus } from "@/types/runDiff";
import {
  cappedNote,
  countsSentence,
  differenceCount,
  fieldLines,
  formatValue,
  groupSections,
  isRunId,
  searchRuns,
  sideLines,
  siblingRuns,
  STATUS_META,
  statusWord,
  visibleRows,
} from "../runDiff";

function counts(partial: Partial<Record<DiffStatus, number>>): Record<DiffStatus, number> {
  return {
    added: 0,
    removed: 0,
    changed: 0,
    unchanged: 0,
    only_in_a: 0,
    only_in_b: 0,
    ...partial,
  };
}

function row(key: string, status: DiffStatus): DiffRow {
  return {
    key,
    label: key,
    status,
    a: status === "added" || status === "only_in_b" ? null : { value: key },
    b: status === "removed" || status === "only_in_a" ? null : { value: key },
    changes: [],
    evidence: { a: [], b: [] },
    note: null,
  };
}

function section(key: string, group: string, rows: DiffRow[]): DiffSection {
  const c = counts({});
  for (const r of rows) c[r.status] += 1;
  return {
    key,
    group,
    title: key,
    match_key: "the key",
    keyed: true,
    recorded: { a: true, b: true },
    counts: c,
    rows,
    notes: [],
    section_evidence: { a: [], b: [] },
  };
}

function job(id: string, extra: Partial<JobDTO> = {}): JobDTO {
  return {
    id,
    sample_id: "s1",
    sample_sha256: "ab".repeat(32),
    sample_filename: "invoice.exe",
    status: "completed",
    config: null,
    created_at: "2026-09-20T10:00:00Z",
    started_at: null,
    completed_at: null,
    duration_seconds: null,
    error_message: null,
    ...extra,
  };
}

describe("status words", () => {
  it("gives every status a word and a mark, so none is told by colour alone", () => {
    for (const meta of Object.values(STATUS_META)) {
      expect(meta.label.length).toBeGreaterThan(0);
      expect(meta.mark.length).toBe(1);
    }
    const marks = Object.values(STATUS_META).map((m) => m.mark);
    expect(new Set(marks).size).toBe(marks.length);
  });
});

describe("visibleRows", () => {
  const s = section("x", "g", [
    row("same", "unchanged"),
    row("new", "added"),
    row("gone", "removed"),
    row("moved", "changed"),
    row("a-only", "only_in_a"),
  ]);

  it("lists differences first and hides the unchanged rows unless asked", () => {
    expect(visibleRows(s, false).map((r) => r.key)).toEqual(["moved", "new", "gone", "a-only"]);
    expect(visibleRows(s, true).map((r) => r.key).at(-1)).toBe("same");
  });

  it("keeps the record's order among rows of one status", () => {
    const t = section("y", "g", [row("b", "added"), row("a", "added")]);
    expect(visibleRows(t, false).map((r) => r.key)).toEqual(["b", "a"]);
  });
});

describe("counts in words", () => {
  it("names the differences and leaves the unchanged count out", () => {
    const c = counts({ changed: 2, added: 1, unchanged: 9 });
    expect(countsSentence(c)).toBe("2 changed, 1 added in b");
    expect(differenceCount(c)).toBe(3);
  });

  it("says plainly when nothing differs and when nothing was recorded", () => {
    expect(countsSentence(counts({ unchanged: 4 }))).toBe("No differences in 4 rows");
    expect(countsSentence(counts({}))).toBe("Nothing recorded");
  });
});

describe("values", () => {
  it("says an absent value is not recorded rather than printing a blank", () => {
    expect(formatValue(null)).toBe("not recorded");
    expect(formatValue(undefined)).toBe("not recorded");
    expect(formatValue("")).toBe("not recorded");
    expect(formatValue(0)).toBe("0");
    expect(formatValue(false)).toBe("no");
    expect(formatValue([])).toBe("none");
    expect(formatValue(["a", 1])).toBe("a, 1");
  });

  it("writes one side's fields as name and value", () => {
    expect(fieldLines({ stated_by: "judge", value: null })).toEqual([
      "who stated it: judge",
      "value: not recorded",
    ]);
    expect(fieldLines(null)).toEqual([]);
  });
});

describe("groupSections", () => {
  it("keeps the API's order of groups and of sections within one", () => {
    const grouped = groupSections([
      section("verdict", "Verdict", []),
      section("key_findings", "Findings", []),
      section("analysts", "Findings", []),
    ]);
    expect(grouped.map(([g, list]) => [g, list.map((s) => s.key)])).toEqual([
      ["Verdict", ["verdict"]],
      ["Findings", ["key_findings", "analysts"]],
    ]);
  });
});

describe("choosing the other run", () => {
  const self = job("self", { created_at: "2026-09-21T00:00:00Z" });
  const jobs = [
    self,
    job("older", { created_at: "2026-09-19T00:00:00Z" }),
    job("newer", { created_at: "2026-09-22T00:00:00Z" }),
    job("other-sample", { sample_id: "s2", sample_sha256: "cd".repeat(32), sample_filename: "b.dll" }),
    job("running", { status: "running" }),
  ];

  it("offers the same sample's completed runs first, newest first, never the run itself", () => {
    expect(siblingRuns(jobs, self).map((j) => j.id)).toEqual(["newer", "older"]);
    expect(siblingRuns(jobs, null)).toEqual([]);
  });

  it("finds any completed run by id, file name or digest", () => {
    expect(searchRuns(jobs, "B.DLL", "self").map((j) => j.id)).toEqual(["other-sample"]);
    expect(searchRuns(jobs, "cdcd", "self").map((j) => j.id)).toEqual(["other-sample"]);
    expect(searchRuns(jobs, "", "self").map((j) => j.id)).not.toContain("running");
  });

  it("recognises a whole run id typed in", () => {
    expect(isRunId(" 2f0b4c10-6f7e-5b6a-9d3b-1f6a5c7e8d90 ")).toBe(true);
    expect(isRunId("2f0b4c10")).toBe(false);
  });
});

describe("a changed row", () => {
  const onlyWho: DiffRow = {
    ...row("severity", "changed"),
    a: { value: "High", stated_by: null },
    b: { value: "High", stated_by: "judge" },
    changes: [{ field: "stated_by", a: null, b: "judge" }],
  };

  it("names what changed, so a change of who stated it is not read as a change of value", () => {
    expect(statusWord(onlyWho)).toBe("Changed: who stated it");
    expect(statusWord(row("x", "added"))).toBe("Added in B");
  });

  it("keeps the value that did not change in view on both sides", () => {
    expect(sideLines(onlyWho, "a")).toEqual([
      "value: High (same in both)",
      "who stated it: not recorded",
    ]);
    expect(sideLines(onlyWho, "b")).toEqual([
      "value: High (same in both)",
      "who stated it: judge",
    ]);
  });
});

describe("a capped section on paper", () => {
  it("says how many rows it holds of how many", () => {
    expect(cappedNote(200, 350)).toBe(
      "Showing 200 of 350 rows; open the page and choose Show all to see the rest.",
    );
    expect(cappedNote(12, 12)).toBeNull();
  });
});
