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

  it("keeps the full id behind a name and behind the eight characters that stand in for one", () => {
    const [named] = auditRows([log({})]);
    expect(named.actor).toBe("Ada Lovelace");
    expect(named.actorId).toBe("6f1d9a2e-0000-4000-8000-000000000000");

    // The cell shows eight characters; the whole id stays reachable.
    const [unnamed] = auditRows([log({ actor: null })]);
    expect(unnamed.actor).toBe("6f1d9a2e");
    expect(unnamed.actorId).toBe("6f1d9a2e-0000-4000-8000-000000000000");

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
    // The cell cuts the id; the row keeps all of it for the cell's title.
    expect(row.resourceId).toBe("abcdef1234567890");
  });

  it("carries what the entry recorded beyond its columns", () => {
    const [row] = auditRows([
      log({
        action: "api_key.create",
        details: { prefix: "mlj_ab12", keys: ["core.a", "core.b"], count: 2, note: null },
      }),
    ]);
    expect(row.details).toEqual([
      ["prefix", "mlj_ab12"],
      ["keys", '["core.a","core.b"]'],
      ["count", "2"],
      ["note", "null"],
    ]);
    expect(auditColumns([row]).details).toBe(true);
  });

  it("carries no details for an entry that recorded none", () => {
    const [row] = auditRows([log({ details: null })]);
    expect(row.details).toEqual([]);
  });
});

describe("the columns a page earns", () => {
  it("draws neither column when every row leaves both empty", () => {
    expect(auditColumns(auditRows([log({}), log({ id: "2" })]))).toEqual({
      resource: false,
      ip: false,
      details: false,
    });
  });

  it("draws a column as soon as one row has something to put in it", () => {
    const rows = auditRows([log({}), log({ id: "2", ip_address: "10.0.0.4" })]);
    expect(auditColumns(rows)).toEqual({ resource: false, ip: true, details: false });
  });
});
