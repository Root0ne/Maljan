import { describe, expect, it } from "vitest";
import { work } from "../ParticipantsBar";

const p = { key: "a", messages: 2 } as never;

describe("participant work line (WB-L7)", () => {
  it("says the count is unavailable rather than 0 tools", () => {
    expect(work(p, {}, false, true)).toBe("2 said · tool count unavailable");
  });
  it("keeps the counted wording", () => {
    expect(work(p, { a: 1 }, false)).toBe("2 said · 1 tool");
    expect(work(p, { a: 3 }, true)).toBe("2 said · 3+ tools");
  });
});
