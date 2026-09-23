/**
 * One server's tools as a table: which the model may call, which the server
 * says it cannot answer on its host, and what a search narrows the list to.
 *
 * It edits the per-server tick list and nothing else. `null` is how a
 * built-in says "every tool"; the first edit through this table turns that
 * into the explicit list, as a single tick always has, so a later change to the
 * server's manifest cannot silently widen what the model sees. A name on the
 * list that the manifest no longer offers is kept where it is: this table did
 * not put it there and cannot see it, so it does not take it away either.
 */

import type { CapabilityCell, ProbeResult } from "@/types/settings";

export interface ToolRow {
  name: string;
  enabled: boolean;
  /** False only where the capability manifest says so; a server that offers
   *  no manifest says nothing and every row reads as available. */
  available: boolean;
  /** The manifest's reason, its remedy and what the tool still answers
   *  without the missing part, in one line. Empty for an available tool. */
  reason: string;
}

/** The capability cells of a probe result, by tool name. */
export function capabilityCells(result: ProbeResult | null | undefined): Map<string, CapabilityCell> {
  const details = result?.details as { capabilities?: { tools?: unknown } } | null | undefined;
  const cells = details?.capabilities?.tools;
  const byName = new Map<string, CapabilityCell>();
  if (!Array.isArray(cells)) return byName;
  for (const cell of cells as CapabilityCell[]) {
    if (cell && typeof cell.name === "string") byName.set(cell.name, cell);
  }
  return byName;
}

/** The one line an unavailable tool's reason is said in. */
export function unavailableReason(cell: CapabilityCell): string {
  return [
    cell.reason ?? "unavailable",
    cell.without ? `still answers ${cell.without}` : "",
    cell.remediation ?? "",
  ]
    .filter(Boolean)
    .join("; ");
}

/** Whether a tool is on the list. `null` is every tool. */
export function isEnabled(allowed: string[] | null, tool: string): boolean {
  return allowed === null || allowed.includes(tool);
}

/** How many of the manifest's tools the model may call. */
export function enabledCount(manifest: string[], allowed: string[] | null): number {
  return manifest.filter((tool) => isEnabled(allowed, tool)).length;
}

/** The manifest's tools whose name holds the query, in the manifest's order. */
export function matchingTools(manifest: string[], query: string): string[] {
  const wanted = query.trim().toLowerCase();
  if (!wanted) return manifest;
  return manifest.filter((tool) => tool.toLowerCase().includes(wanted));
}

/** The rows the table draws. */
export function toolRows(
  manifest: string[],
  allowed: string[] | null,
  cells: Map<string, CapabilityCell>,
  query: string,
): ToolRow[] {
  return matchingTools(manifest, query).map((name) => {
    const cell = cells.get(name);
    const available = cell?.available !== false;
    return {
      name,
      enabled: isEnabled(allowed, name),
      available,
      reason: available || !cell ? "" : unavailableReason(cell),
    };
  });
}

/**
 * The tick list after turning `tools` on or off together.
 *
 * The manifest's tools come out in the manifest's order, and any name the
 * list held that the manifest does not offer stays at the end, untouched.
 */
export function setTools(
  manifest: string[],
  allowed: string[] | null,
  tools: string[],
  on: boolean,
): string[] {
  const base = new Set(allowed === null ? manifest : allowed);
  for (const tool of tools) {
    if (on) base.add(tool);
    else base.delete(tool);
  }
  const offered = new Set(manifest);
  const kept = (allowed ?? []).filter((tool) => !offered.has(tool) && base.has(tool));
  return [...manifest.filter((tool) => base.has(tool)), ...kept];
}
