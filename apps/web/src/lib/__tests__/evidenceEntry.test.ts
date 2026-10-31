import { beforeEach, describe, expect, it, vi } from "vitest";

const getJobEvidence = vi.fn();
vi.mock("@/lib/api", () => ({ api: { getJobEvidence: (...args: unknown[]) => getJobEvidence(...args) } }));

import { loadEvidenceEntry, resetEvidenceEntries } from "@/lib/evidenceEntry";

/**
 * Reading one record of the evidence ledger by its id, for a tool call opened
 * in the conversation: the page is worked out from the id, read once for
 * every call on it, and read again only when it predates the record.
 */

function entry(id: string) {
  return { entry_id: id, output: `output of ${id}` };
}

beforeEach(() => {
  resetEvidenceEntries();
  getJobEvidence.mockReset();
});

describe("loadEvidenceEntry", () => {
  it("reads the page the id falls on, once for every call on it", async () => {
    getJobEvidence.mockResolvedValue({ entries: [entry("ev_0051"), entry("ev_0052")] });
    await expect(loadEvidenceEntry("job", "ev_0052")).resolves.toMatchObject({ entry_id: "ev_0052" });
    await expect(loadEvidenceEntry("job", "ev_0051")).resolves.toMatchObject({ entry_id: "ev_0051" });
    expect(getJobEvidence).toHaveBeenCalledTimes(1);
    expect(getJobEvidence).toHaveBeenCalledWith("job", { page: 2, pageSize: 50 });
  });

  it("asks again, once, for a page read before the record existed", async () => {
    getJobEvidence.mockResolvedValueOnce({ entries: [entry("ev_0001")] });
    await loadEvidenceEntry("job", "ev_0001");
    getJobEvidence.mockResolvedValueOnce({ entries: [entry("ev_0001"), entry("ev_0002")] });
    await expect(loadEvidenceEntry("job", "ev_0002")).resolves.toMatchObject({ entry_id: "ev_0002" });
    expect(getJobEvidence).toHaveBeenCalledTimes(2);
  });

  it("answers null for an id that is not a ledger id, without asking", async () => {
    await expect(loadEvidenceEntry("job", "pack:1")).resolves.toBeNull();
    expect(getJobEvidence).not.toHaveBeenCalled();
  });

  it("does not remember a failed read", async () => {
    getJobEvidence.mockRejectedValueOnce(new Error("offline"));
    await expect(loadEvidenceEntry("job", "ev_0003")).rejects.toThrow("offline");
    getJobEvidence.mockResolvedValueOnce({ entries: [entry("ev_0003")] });
    await expect(loadEvidenceEntry("job", "ev_0003")).resolves.toMatchObject({ entry_id: "ev_0003" });
  });
});
