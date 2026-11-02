import { describe, expect, it } from "vitest";

import type { ToolRefEntry } from "@/types/settings";
import {
  namedProviders,
  offeredProviders,
  providerRef,
  sameToolRef,
} from "../capabilityRefs";

/** The shape the API stores an unnamed provider reference in, unchanged. */
const OWN: ToolRefEntry = { kind: "provider", server: null, name: null };

describe("provider references that name their provider", () => {
  it("writes the agent's own provider exactly as the API stores it", () => {
    expect(providerRef(null)).toEqual(OWN);
    expect("provider" in providerRef(null)).toBe(false);
  });

  it("writes a named provider with its id", () => {
    expect(providerRef("prov_b")).toEqual({
      kind: "provider",
      server: null,
      name: null,
      provider: "prov_b",
    });
  });

  it("tells the own provider from a named one, and two named ones apart", () => {
    expect(sameToolRef(OWN, providerRef(null))).toBe(true);
    expect(sameToolRef(OWN, { ...OWN, provider: null })).toBe(true);
    expect(sameToolRef(OWN, providerRef("prov_a"))).toBe(false);
    expect(sameToolRef(providerRef("prov_a"), providerRef("prov_b"))).toBe(false);
    expect(sameToolRef(providerRef("prov_a"), providerRef("prov_a"))).toBe(true);
  });

  it("lists the providers a tool list names, each once, in order", () => {
    const tools = [OWN, providerRef("prov_b"), providerRef("prov_a"), providerRef("prov_b")];
    expect(namedProviders(tools)).toEqual(["prov_b", "prov_a"]);
  });

  it("offers the deployment's providers but none, and keeps one no longer offered", () => {
    const tools = [providerRef("gone")];
    expect(offeredProviders(tools, ["none", "prov_a", "prov_b"])).toEqual([
      "prov_a",
      "prov_b",
      "gone",
    ]);
    expect(offeredProviders([], ["prov_a"])).toEqual(["prov_a"]);
  });
});
