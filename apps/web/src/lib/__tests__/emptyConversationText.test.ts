import { describe, expect, it } from "vitest";
import { emptyConversationText } from "@/lib/conversation";

describe("empty conversation text (WB-L5)", () => {
  it("does not blame retention when the feed failed to load", () => {
    const text = emptyConversationText({ live: false, eventCount: 0, feedError: "stopped" });
    expect(text).not.toMatch(/retention/i);
    expect(text).toMatch(/could not be read/i);
  });
  it("names retention only for a feed that answered empty", () => {
    expect(emptyConversationText({ live: false, eventCount: 0, feedError: null })).toMatch(/retention/);
  });
  it("keeps the live and filter wording", () => {
    expect(emptyConversationText({ live: true, eventCount: 0, feedError: null })).toMatch(/Waiting/);
    expect(emptyConversationText({ live: false, eventCount: 3, feedError: null })).toMatch(/filters/);
  });
});
