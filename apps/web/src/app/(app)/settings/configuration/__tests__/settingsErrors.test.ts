import { describe, expect, it } from "vitest";
import { withoutErrorsFor } from "../useSettings";

const errors = {
  "core.agents.definitions.ahmet.prompt": "a generic agent needs a prompt",
  "core.agents.definitions.judge": "'judge' is built in; clone it to change it",
  "core.agents.definitionsuffix": "a key that only looks like a child",
  "core.llm.max_tokens": "must be a positive integer",
};

describe("clearing what the server said about a leaf", () => {
  it("drops every message nested under the edited leaf", () => {
    expect(withoutErrorsFor(errors, "core.agents.definitions")).toEqual({
      "core.agents.definitionsuffix": "a key that only looks like a child",
      "core.llm.max_tokens": "must be a positive integer",
    });
  });

  it("drops a scalar leaf's own message", () => {
    expect(withoutErrorsFor(errors, "core.llm.max_tokens")).not.toHaveProperty(
      "core.llm.max_tokens",
    );
  });

  it("returns the same object when there was nothing to drop", () => {
    expect(withoutErrorsFor(errors, "core.llm.provider")).toBe(errors);
  });
});
