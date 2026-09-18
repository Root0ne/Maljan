import { describe, expect, it } from "vitest";
import { probeDetail } from "../probeDetail";

describe("what a failed probe says", () => {
  it("says what a refused connection means, and keeps the class", () => {
    expect(probeDetail("model list: ConnectError: All connection attempts failed")).toBe(
      "nothing answered at that address — check the host and the port, and that the " +
        "server is running (model list: ConnectError: All connection attempts failed)",
    );
  });

  it("tells a timeout from a refusal", () => {
    expect(probeDetail("ReadTimeout")).toContain("did not answer in time");
  });

  it("leaves a message the API already wrote in words alone", () => {
    const written = "the model 'qwen3:8b' is not served by this endpoint";
    expect(probeDetail(written)).toBe(written);
  });

  it("answers for an empty detail", () => {
    expect(probeDetail("")).toBe("");
  });
});
