import { describe, expect, it } from "vitest";
import { actionLabel, actorLabel, auditColumns, auditRows } from "../auditRows";
import type { AuditLogDTO } from "@/lib/api";

function log(overrides: Partial<AuditLogDTO>): AuditLogDTO {
  return {
    id: "1",
    user_id: "6f1d9a2e-0000-4000-8000-000000000000",
    actor: "Ada Lovelace",
    action: "settings.update",
    resource_type: "settings",
    resource_id: null,
    details: null,
    ip_address: null,
    created_at: "2026-09-17T09:00:00Z",
    ...overrides,
  };
}

describe("an audit row", () => {
  it("reads the action key as a sentence", () => {
    expect(actionLabel("settings.update")).toBe("Settings update");
    expect(actionLabel("api_key.revoke")).toBe("API key revoke");
  });

  it("names the actor the endpoint names", () => {
    expect(actorLabel("Ada Lovelace", "6f1d9a2e-0000-4000-8000-000000000000")).toBe(
      "Ada Lovelace"
    );
  });

  it("falls back to the id when the endpoint has no name for it", () => {
    expect(actorLabel(null, "6f1d9a2e-0000-4000-8000-000000000000")).toBe("6f1d9a2e");
    expect(actorLabel("   ", "6f1d9a2e-0000-4000-8000-000000000000")).toBe("6f1d9a2e");
  });

  it("names the platform where there is no principal at all", () => {
    expect(actorLabel(null, null)).toBe("the platform");
    expect(actorLabel("", "  ")).toBe("the platform");
  });

  it("keeps the id beside a name, and does not repeat an id it already shows", () => {
    const [named] = auditRows([log({})]);
    expect(named.actor).toBe("Ada Lovelace");
    expect(named.actorId).toBe("6f1d9a2e-0000-4000-8000-000000000000");

    const [unnamed] = auditRows([log({ actor: null })]);
    expect(unnamed.actor).toBe("6f1d9a2e");
    expect(unnamed.actorId).toBe("");

    const [platform] = auditRows([log({ actor: null, user_id: null })]);
    expect(platform.actor).toBe("the platform");
    expect(platform.actorId).toBe("");
  });

  it("drops a resource that only restates the action's own prefix", () => {
    const [row] = auditRows([log({})]);
    expect(row.resource).toBe("");
  });

  it("keeps a resource that says something the action does not", () => {
    const [row] = auditRows([
      log({ action: "job.cancel", resource_type: "sample", resource_id: "abcdef1234567890" }),
    ]);
    expect(row.resource).toBe("sample abcdef12");
  });
});

describe("the columns a page earns", () => {
  it("draws neither column when every row leaves both empty", () => {
    expect(auditColumns(auditRows([log({}), log({ id: "2" })]))).toEqual({
      resource: false,
      ip: false,
    });
  });

  it("draws a column as soon as one row has something to put in it", () => {
    const rows = auditRows([log({}), log({ id: "2", ip_address: "10.0.0.4" })]);
    expect(auditColumns(rows)).toEqual({ resource: false, ip: true });
  });
});
