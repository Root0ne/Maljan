import { describe, expect, it } from "vitest";

import AgentFormStep, { agentStepSection } from "../steps/AgentFormStep";
import ProfilePickerStep from "../steps/ProfilePickerStep";
import RestMappingStep from "../steps/RestMappingStep";
import ServerFormStep, { serverStepSection } from "../steps/ServerFormStep";
import VirustotalStep, { QUOTA_NOTE, SUBMIT_NOTE } from "../steps/VirustotalStep";

/**
 * The four step components are reachable code before any guide declares them
 * (the guides declare them later), so nothing else would notice if one of them
 * stopped compiling or lost its default export. This mounts nothing — there
 * is no jsdom here — it only proves each module loads and still exports the
 * component `GuidePage`'s switch renders.
 */
describe("guide step components", () => {
  it("each module default-exports a component", () => {
    for (const component of [
      ServerFormStep,
      AgentFormStep,
      ProfilePickerStep,
      RestMappingStep,
      VirustotalStep,
    ]) {
      expect(typeof component).toBe("function");
    }
  });

  it("the VirusTotal step says what the token costs and what stays off", () => {
    expect(QUOTA_NOTE).toContain("quota");
    expect(QUOTA_NOTE).toContain("429");
    expect(SUBMIT_NOTE).toContain("upload the sample");
  });

  it("a section a guide did not name falls back to the first one", () => {
    expect(serverStepSection("tools")).toBe("tools");
    expect(serverStepSection(undefined)).toBe("connection");
    expect(serverStepSection("identity")).toBe("connection");
    expect(agentStepSection("resolve")).toBe("resolve");
    expect(agentStepSection(undefined)).toBe("identity");
    expect(agentStepSection("connection")).toBe("identity");
  });
});
