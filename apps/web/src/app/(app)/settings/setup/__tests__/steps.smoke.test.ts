import { describe, expect, it } from "vitest";

import AgentFormStep, { agentStepSection } from "../steps/AgentFormStep";
import ProfilePickerStep from "../steps/ProfilePickerStep";
import RestMappingStep from "../steps/RestMappingStep";
import ServerFormStep, { serverStepSection } from "../steps/ServerFormStep";
import CredentialStep, { obtainedLine } from "../steps/CredentialStep";
import served from "@/test-fixtures/settings-schema.json";
import type { SettingsSchema } from "@/types/settings";

/**
 * The step components are reachable code before any guide declares them
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
      CredentialStep,
    ]) {
      expect(typeof component).toBe("function");
    }
  });

  it("the shipped credential step says what the token costs and what stays off", () => {
    // The words are the server's declared note, served on the schema.
    const note = (served as unknown as SettingsSchema).credential_servers?.virustotal?.note ?? "";
    expect(note).toContain("quota");
    expect(note).toContain("429");
    expect(note).toContain("upload the sample");
  });

  it("reports what came back as the button always did", () => {
    expect(
      obtainedLine({
        server: "virustotal",
        enabled: true,
        transport: "streamable-http",
        url: "https://ai.virustotal.com/mcp",
        auth_token: "**********",
        facts: { public_handle: "Agent#1", agent_id: "agt_1" },
        tools: null,
      })
    ).toBe("registered as Agent#1 · https://ai.virustotal.com/mcp · token stored");
    expect(
      obtainedLine({
        server: "invented",
        enabled: true,
        transport: "sse",
        url: "",
        auth_token: "**********",
        facts: { public_handle: "", agent_id: "agt_2" },
        tools: [],
      })
    ).toBe("registered as agt_2 · token stored");
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
