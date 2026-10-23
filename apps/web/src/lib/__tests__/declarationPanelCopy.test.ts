import { describe, expect, it } from "vitest";
import { DECLARATION_PANEL_COPY } from "@/app/(app)/settings/configuration/declarationFields";

describe("declaration panel copy (WA-L12)", () => {
  it("does not claim only one field is read", () => {
    expect(DECLARATION_PANEL_COPY).not.toMatch(/nothing reads/i);
    expect(DECLARATION_PANEL_COPY).not.toMatch(/besides\s+sample_open/i);
  });
});
