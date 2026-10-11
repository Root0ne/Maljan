/**
 * A definition's tool references, read with its capability references.
 *
 * A `kind: "capability"` reference (`capability: "reputation"`) stands for the
 * servers the API serves for it on the agent definitions' catalogue entry
 * (`capability_servers`), as resolution reads them. The editor draws a server
 * a capability reaches as ticked, so a built-in agent shows the tools it has,
 * and draws the capability as a row of its own that a clone can untick. The
 * console keeps no rule of its own about which servers a capability reaches.
 */

import type { ToolRefEntry } from "@/types/settings";

export type CapabilityServers = Record<string, readonly string[]>;

/** Whether two references are the same reference, every field compared. */
export function sameToolRef(a: ToolRefEntry, b: ToolRefEntry): boolean {
  return (
    a.kind === b.kind &&
    a.server === b.server &&
    a.name === b.name &&
    (a.agent ?? null) === (b.agent ?? null) &&
    (a.capability ?? null) === (b.capability ?? null)
  );
}

/** One capability reference, in the shape the API stores it. */
export function capabilityRef(capability: string): ToolRefEntry {
  return { kind: "capability", server: null, name: null, capability };
}

/** The capabilities this list holds that reach `server`. */
export function capabilitiesReaching(
  tools: readonly ToolRefEntry[],
  server: string,
  reach: CapabilityServers,
): string[] {
  return tools
    .filter((t) => t.kind === "capability" && t.capability)
    .map((t) => String(t.capability))
    .filter((cap) => (reach[cap] ?? []).includes(server));
}

/** Whether the list holds `server` whole: by its own reference, or by a capability. */
export function holdsServer(
  tools: readonly ToolRefEntry[],
  server: string,
  reach: CapabilityServers,
): boolean {
  return (
    tools.some((t) => t.kind === "mcp" && t.server === server && t.name === null) ||
    capabilitiesReaching(tools, server, reach).length > 0
  );
}

/** The list without `server` whole: its own reference and every capability that reaches it. */
export function withoutServer(
  tools: readonly ToolRefEntry[],
  server: string,
  reach: CapabilityServers,
): ToolRefEntry[] {
  const reaching = new Set(capabilitiesReaching(tools, server, reach));
  return tools.filter(
    (t) =>
      !(t.kind === "mcp" && t.server === server && t.name === null) &&
      !(t.kind === "capability" && reaching.has(String(t.capability))),
  );
}

/** The capability rows to draw: those the API serves, then any other this list holds. */
export function offeredCapabilities(
  tools: readonly ToolRefEntry[],
  reach: CapabilityServers,
): string[] {
  const held = tools
    .filter((t) => t.kind === "capability" && t.capability)
    .map((t) => String(t.capability));
  return [...new Set([...Object.keys(reach), ...held])];
}
