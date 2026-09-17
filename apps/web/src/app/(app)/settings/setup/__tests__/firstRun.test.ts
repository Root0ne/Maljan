import { describe, expect, it } from "vitest";

import { GUIDES, guidesFor } from "../guides";

describe("what the hub offers before there is a model", () => {
  it("offers the four a first run needs, in the order they are met", () => {
    expect(guidesFor(false).map((g) => g.id)).toEqual(["llm", "static", "sandbox", "agent"]);
  });

  it("offers all of them once a model is connected", () => {
    expect(guidesFor(true)).toEqual(GUIDES);
  });

  it("puts the model first, since the other three are tested against it", () => {
    expect(guidesFor(false)[0].id).toBe("llm");
  });
});
