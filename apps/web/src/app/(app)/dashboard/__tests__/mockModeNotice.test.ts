import { describe, expect, it } from "vitest";

import { mockModeNotice } from "../mockModeNotice";

describe("the mock-mode warning", () => {
  it("is red when the status says mock runs are allowed", () => {
    expect(mockModeNotice({ mock_mode_allowed: true }, null)).toEqual({ kind: "allowed" });
  });

  it("is absent when the status says they are not", () => {
    expect(mockModeNotice({ mock_mode_allowed: false }, null)).toBeNull();
  });

  it("says the gate is unknown when the status could not be read", () => {
    expect(mockModeNotice(null, "Failed to fetch")).toEqual({ kind: "unknown", reason: "Failed to fetch" });
  });
});
