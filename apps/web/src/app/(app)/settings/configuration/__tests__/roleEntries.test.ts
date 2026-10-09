import { describe, expect, it } from "vitest";
import { ROLE_ENTRIES, ROLE_ENTRY_KEYS, roleEntryChanged, roleKeyError } from "../roleEntries";

describe("the roles with no definition", () => {
  it("are the mediator and the function summariser, under the keys the API reads", () => {
    expect(ROLE_ENTRIES.map((role) => role.key)).toEqual(["mediator", "summarizer"]);
    expect([...ROLE_ENTRY_KEYS]).toEqual(["mediator", "summarizer"]);
  });

  it("say what an absent entry runs on", () => {
    for (const role of ROLE_ENTRIES) {
      expect(role.description).toContain("global expert model");
    }
  });

  it("say that a judge entry does not move the mediator", () => {
    expect(ROLE_ENTRIES[0].description).toContain("judge");
  });
});

describe("roleKeyError", () => {
  it("refuses an agent named after a role", () => {
    expect(roleKeyError("mediator")).toMatch(/mediator/);
    expect(roleKeyError("summarizer")).toMatch(/summari/);
  });

  it("lets any other name through", () => {
    expect(roleKeyError("mediator_custom")).toBeNull();
    expect(roleKeyError("strings")).toBeNull();
  });
});

describe("roleEntryChanged", () => {
  it("is false while the staged entry is the saved one", () => {
    const saved = { mediator: { provider: "openai", model: "m" } };
    expect(roleEntryChanged("mediator", { ...saved }, saved)).toBe(false);
    expect(roleEntryChanged("summarizer", {}, {})).toBe(false);
  });

  it("is true once the entry is added, changed or removed", () => {
    const saved = { mediator: { provider: "openai", model: "m" } };
    expect(roleEntryChanged("mediator", {}, saved)).toBe(true);
    expect(roleEntryChanged("mediator", { mediator: { provider: "openai", model: "n" } }, saved)).toBe(
      true
    );
    expect(roleEntryChanged("summarizer", { summarizer: { provider: "openai", model: "s" } }, {})).toBe(
      true
    );
  });
});
