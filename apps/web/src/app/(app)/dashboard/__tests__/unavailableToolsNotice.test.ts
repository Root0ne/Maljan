/**
 * What the dashboard says about a tool the default team would call and the
 * host cannot run: nothing while every tool is there, and otherwise each tool
 * with where it is missing, why, and what to run.
 */

import { describe, expect, it } from "vitest";

import { unavailableToolsNotice } from "@/app/(app)/dashboard/unavailableToolsNotice";
import type { UnavailableToolDTO } from "@/lib/api";

const CAPA: UnavailableToolDTO = {
  server: "analysis",
  tool: "capa",
  reason: "capa is not installed (No module named 'capa')",
  remediation: "install capa on the host that runs this server: uv sync --extra capa",
  still_answers: "",
  degradation_reason:
    "server.analysis.capa_unavailable(capa is not installed (No module named 'capa')); " +
    "install capa on the host that runs this server: uv sync --extra capa",
};

const PY7ZR: UnavailableToolDTO = {
  server: "analysis",
  tool: "archive_list",
  reason: "py7zr is not installed (No module named 'py7zr')",
  remediation: "install the optional tool libraries on the host that runs this server: uv sync --extra tools",
  still_answers: "zip and tar members; 7z needs py7zr",
  degradation_reason: "server.analysis.archive_list_unavailable(...)",
};

describe("the unavailable tools notice", () => {
  it("says nothing when the status lists none or does not carry the field", () => {
    expect(unavailableToolsNotice(undefined)).toBeNull();
    expect(unavailableToolsNotice(null)).toBeNull();
    expect(unavailableToolsNotice([])).toBeNull();
  });

  it("names the tool, the server, the reason and the remedy", () => {
    const notice = unavailableToolsNotice([CAPA]);

    expect(notice?.label).toBe("Tool unavailable");
    expect(notice?.detail).toContain("still accepted");
    expect(notice?.lines).toEqual([
      "capa on analysis: capa is not installed (No module named 'capa'). " +
        "To fix: install capa on the host that runs this server: uv sync --extra capa.",
    ]);
  });

  it("says what a tool still answers, and counts them when there are several", () => {
    const notice = unavailableToolsNotice([CAPA, PY7ZR]);

    expect(notice?.label).toBe("2 tools unavailable");
    expect(notice?.lines[1]).toContain("It still answers zip and tar members; 7z needs py7zr.");
  });
});
